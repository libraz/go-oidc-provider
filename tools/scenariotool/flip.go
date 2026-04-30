package main

import (
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
	if !validStatuses[newStatus] {
		return fmt.Errorf("flip: status %q must be active|pending|out-of-scope", newStatus)
	}
	if newStatus == "out-of-scope" && strings.TrimSpace(reason) == "" {
		return fmt.Errorf("flip: status=out-of-scope requires --reason")
	}
	if newStatus != "out-of-scope" && reason != "" {
		return fmt.Errorf("flip: --reason is only allowed when flipping to out-of-scope")
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
	if current == newStatus {
		if newStatus != "out-of-scope" || strings.TrimSpace(r.OutOfScopeReason) == strings.TrimSpace(reason) {
			fmt.Printf("scenariotool: %s already at status=%s — no-op\n", id, newStatus)
			return nil
		}
	}

	raw, err := os.ReadFile(r.File.Path) //nolint:gosec // catalog path is operator-controlled.
	if err != nil {
		return err
	}
	edited, err := flipStatusInYAML(raw, id, newStatus, reason)
	if err != nil {
		return err
	}
	if err := os.WriteFile(r.File.Path, edited, 0o600); err != nil {
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

var (
	flipRowStartLine    = regexp.MustCompile(`^  - id:\s*(\S+)`)
	flipStatusFieldLine = regexp.MustCompile(`^    status:\s*`)
	flipReasonFieldLine = regexp.MustCompile(`^    out_of_scope_reason:\s*`)
)

// flipStatusInYAML rewrites the status (and optionally
// out_of_scope_reason) of one row inside a catalog YAML byte slice.
// The function preserves trailing newline behaviour and only touches
// lines belonging to the targeted row.
func flipStatusInYAML(raw []byte, id, newStatus, reason string) ([]byte, error) {
	hadTrailingNewline := len(raw) > 0 && raw[len(raw)-1] == '\n'
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")

	rowStart := -1
	for i, line := range lines {
		m := flipRowStartLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if m[1] == id {
			rowStart = i
			break
		}
	}
	if rowStart < 0 {
		return nil, fmt.Errorf("flipStatusInYAML: row %q not found", id)
	}

	rowEnd := len(lines)
	for j := rowStart + 1; j < len(lines); j++ {
		if flipRowStartLine.MatchString(lines[j]) {
			rowEnd = j
			break
		}
	}

	statusLine, reasonLine := -1, -1
	for j := rowStart + 1; j < rowEnd; j++ {
		switch {
		case flipStatusFieldLine.MatchString(lines[j]):
			statusLine = j
		case flipReasonFieldLine.MatchString(lines[j]):
			reasonLine = j
		}
	}

	newStatusLine := "    status: " + newStatus

	switch {
	case statusLine >= 0:
		lines[statusLine] = newStatusLine
	default:
		insertAt := lastMeaningfulRowLine(lines, rowStart, rowEnd) + 1
		lines = insertLines(lines, insertAt, []string{newStatusLine})
		if reasonLine >= insertAt {
			reasonLine++
		}
		rowEnd++
	}

	if newStatus == "out-of-scope" {
		newReasonLine := "    out_of_scope_reason: " + yamlInlineString(reason)
		switch {
		case reasonLine >= 0:
			lines[reasonLine] = newReasonLine
		default:
			anchor := -1
			for j := rowStart + 1; j < rowEnd; j++ {
				if lines[j] == newStatusLine {
					anchor = j
					break
				}
			}
			if anchor < 0 {
				anchor = lastMeaningfulRowLine(lines, rowStart, rowEnd)
			}
			lines = insertLines(lines, anchor+1, []string{newReasonLine})
		}
	} else if reasonLine >= 0 {
		lines = append(lines[:reasonLine], lines[reasonLine+1:]...)
	}

	out := strings.Join(lines, "\n")
	if hadTrailingNewline {
		out += "\n"
	}
	return []byte(out), nil
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
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '#', ':', '"', '\'', '\\', '\n', '\r', '\t':
			return false
		}
	}
	return true
}
