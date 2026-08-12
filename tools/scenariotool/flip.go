package main

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// runFlip toggles a row's status field (and out_of_scope_reason when
// applicable) by editing the YAML file in place. It rewrites only the
// status / reason lines so diffs stay scoped to the targeted row, and
// re-runs full validation against the post-write state to catch any
// fallout the byte-level edit might have introduced.
func runFlip(dir, id, newStatus, reason string) error {
	if err := checkFlipRequest(newStatus, reason); err != nil {
		return err
	}

	cat, err := loadCatalog(dir)
	if err != nil {
		return err
	}
	r := cat.Lookup(id)
	if r == nil {
		return &exitError{code: 1, message: fmt.Sprintf("scenariotool: no row with id %q", id)}
	}

	current := r.EffectiveStatus()
	if flipIsNoOp(r, current, newStatus, reason) {
		fmt.Printf("scenariotool: %s already at status=%s — no-op\n", id, newStatus)
		return nil
	}

	raw, err := os.ReadFile(r.File.Path)
	if err != nil {
		return err
	}
	edited, err := flipStatusInYAML(raw, id, newStatus, reason)
	if err != nil {
		return err
	}
	// The path comes from the directory listing of the operator-supplied
	// catalog directory and is the same file the row was just read from,
	// so the write cannot reach outside the tree the operator named.
	if err := os.WriteFile(r.File.Path, edited, 0o600); err != nil { //nolint:gosec // G703: path is a catalog entry loaded from the operator-supplied directory.
		return err
	}

	cat2, err := loadCatalog(dir)
	if err != nil {
		return fmt.Errorf("flip wrote %s but reload failed: %w", r.File.Path, err)
	}
	if err := cat2.Validate(ValidationOptions{LenientCrossRefs: false}); err != nil {
		return fmt.Errorf("flip wrote %s but validation failed: %w", r.File.Path, err)
	}
	fmt.Printf("scenariotool: %s %s -> %s\n", id, current, newStatus)
	return nil
}

// checkFlipRequest rejects a flip whose target status and reason
// disagree, before anything on disk is touched. out_of_scope_reason is
// mandatory exactly when the target status is out-of-scope, mirroring
// the catalog invariant the post-write validation would otherwise catch
// only after the file was already rewritten.
func checkFlipRequest(newStatus, reason string) error {
	switch {
	case !validStatuses[newStatus]:
		return fmt.Errorf("flip: status %q must be active|pending|out-of-scope", newStatus)
	case newStatus == "out-of-scope" && strings.TrimSpace(reason) == "":
		return errors.New("flip: status=out-of-scope requires --reason")
	case newStatus != "out-of-scope" && reason != "":
		return errors.New("flip: --reason is only allowed when flipping to out-of-scope")
	}
	return nil
}

// flipIsNoOp reports whether the row already says what the flip would
// make it say. Flipping to out-of-scope still rewrites the file when
// only the reason differs, so the operator can correct a reason without
// a detour through another status.
func flipIsNoOp(r *Row, current, newStatus, reason string) bool {
	if current != newStatus {
		return false
	}
	if newStatus != "out-of-scope" {
		return true
	}
	return strings.TrimSpace(r.OutOfScopeReason) == strings.TrimSpace(reason)
}

var (
	flipRowStartLine    = regexp.MustCompile(`^  - id:\s*(\S+)`)
	flipStatusFieldLine = regexp.MustCompile(`^    status:\s*`)
	flipReasonFieldLine = regexp.MustCompile(`^    out_of_scope_reason:\s*`)
)

// flipTarget locates the lines a status flip may touch inside one row:
// the row's own line span, and the indexes of its status /
// out_of_scope_reason fields (-1 when the row does not declare them).
// Indexes are kept together because inserting a line shifts the ones
// below it, and every caller has to see the same shifted view.
type flipTarget struct {
	rowStart, rowEnd       int
	statusLine, reasonLine int
}

// flipStatusInYAML rewrites the status (and optionally
// out_of_scope_reason) of one row inside a catalog YAML byte slice.
// The function preserves trailing newline behaviour and only touches
// lines belonging to the targeted row.
func flipStatusInYAML(raw []byte, id, newStatus, reason string) ([]byte, error) {
	hadTrailingNewline := len(raw) > 0 && raw[len(raw)-1] == '\n'
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")

	target, ok := locateFlipTarget(lines, id)
	if !ok {
		return nil, fmt.Errorf("flipStatusInYAML: row %q not found", id)
	}

	newStatusLine := "    status: " + newStatus
	lines = target.setStatus(lines, newStatusLine)
	lines = target.setReason(lines, newStatusLine, newStatus, reason)

	out := strings.Join(lines, "\n")
	if hadTrailingNewline {
		out += "\n"
	}
	return []byte(out), nil
}

// locateFlipTarget finds the row with the given id and the fields it
// already declares. The row ends where the next `- id:` line begins, or
// at end of file.
func locateFlipTarget(lines []string, id string) (flipTarget, bool) {
	target := flipTarget{rowStart: -1, rowEnd: len(lines), statusLine: -1, reasonLine: -1}
	for i, line := range lines {
		m := flipRowStartLine.FindStringSubmatch(line)
		if m != nil && m[1] == id {
			target.rowStart = i
			break
		}
	}
	if target.rowStart < 0 {
		return target, false
	}
	for j := target.rowStart + 1; j < len(lines); j++ {
		if flipRowStartLine.MatchString(lines[j]) {
			target.rowEnd = j
			break
		}
	}
	for j := target.rowStart + 1; j < target.rowEnd; j++ {
		switch {
		case flipStatusFieldLine.MatchString(lines[j]):
			target.statusLine = j
		case flipReasonFieldLine.MatchString(lines[j]):
			target.reasonLine = j
		}
	}
	return target, true
}

// setStatus replaces the row's status line, or appends one after the
// row's last non-blank line when the row does not declare `status`
// yet. Inserting shifts every index below the insertion point, so the
// target's own bookkeeping is updated in step.
func (t *flipTarget) setStatus(lines []string, newStatusLine string) []string {
	if t.statusLine >= 0 {
		lines[t.statusLine] = newStatusLine
		return lines
	}
	insertAt := lastMeaningfulRowLine(lines, t.rowStart, t.rowEnd) + 1
	lines = insertLines(lines, insertAt, []string{newStatusLine})
	if t.reasonLine >= insertAt {
		t.reasonLine++
	}
	t.statusLine = insertAt
	t.rowEnd++
	return lines
}

// setReason keeps out_of_scope_reason in step with the new status: it
// is written directly under the status line when flipping to
// out-of-scope, and dropped otherwise, because a reason surviving on a
// row that came back in scope would document an exclusion that no
// longer applies.
func (t *flipTarget) setReason(lines []string, newStatusLine, newStatus, reason string) []string {
	if newStatus != "out-of-scope" {
		if t.reasonLine >= 0 {
			return append(lines[:t.reasonLine], lines[t.reasonLine+1:]...)
		}
		return lines
	}
	newReasonLine := "    out_of_scope_reason: " + yamlInlineString(reason)
	if t.reasonLine >= 0 {
		lines[t.reasonLine] = newReasonLine
		return lines
	}
	anchor := indexOfLine(lines, t.rowStart+1, t.rowEnd, newStatusLine)
	if anchor < 0 {
		anchor = lastMeaningfulRowLine(lines, t.rowStart, t.rowEnd)
	}
	return insertLines(lines, anchor+1, []string{newReasonLine})
}

// indexOfLine returns the index of the first line in [from, to) equal
// to want, or -1.
func indexOfLine(lines []string, from, to int, want string) int {
	for j := from; j < to; j++ {
		if lines[j] == want {
			return j
		}
	}
	return -1
}

// lastMeaningfulRowLine returns the index of the last non-blank line
// belonging to the row spanning [rowStart, rowEnd). It is used to find
// the right place to append a brand-new key when one of the optional
// fields is missing entirely.
func lastMeaningfulRowLine(lines []string, rowStart, rowEnd int) int {
	last := rowStart
	for j := rowStart; j < rowEnd; j++ {
		if strings.TrimSpace(lines[j]) != "" {
			last = j
		}
	}
	return last
}

// insertLines splices in zero or more lines at idx without aliasing
// the source slice (the trailing tail is copied so callers can keep
// using the result independently).
func insertLines(lines []string, idx int, inserted []string) []string {
	out := make([]string, 0, len(lines)+len(inserted))
	out = append(out, lines[:idx]...)
	out = append(out, inserted...)
	out = append(out, lines[idx:]...)
	return out
}

// yamlInlineString quotes a value safely as a YAML 1.2 double-quoted
// scalar. It is used for out_of_scope_reason so reasons may contain
// arbitrary punctuation, embedded spec citations, etc.
func yamlInlineString(s string) string {
	s = strings.TrimSpace(s)
	if isYAMLPlainSafe(s) {
		return s
	}
	return strconv.Quote(s)
}

// isYAMLPlainSafe checks whether s can appear unquoted in a YAML flow
// scalar position. The list mirrors the conservative rules YAML 1.2
// applies to plain-style strings; anything risky falls back to a
// double-quoted form via strconv.Quote.
func isYAMLPlainSafe(s string) bool {
	if s == "" {
		return false
	}
	switch s[0] {
	case '!', '&', '*', '-', '?', ':', ',', '[', ']', '{', '}', '#', '|', '>', '\'', '"', '%', '@', '`':
		return false
	}
	for i := range len(s) {
		switch s[i] {
		case '#', ':', '"', '\'', '\\', '\n', '\r', '\t':
			return false
		}
	}
	return true
}
