package main

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// runFlip toggles a row's status field (and its exclusion reason when
// applicable) by editing the YAML file in place. Only the status and
// reason fields of the targeted row change, and the post-write state is
// re-validated; a file that fails that check is put back as it was.
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
		return restoreAfterFlipFailure(r.File.Path, raw, fmt.Errorf("flip wrote %s but reload failed: %w", r.File.Path, err))
	}
	// The re-read asks one question: did the write leave the file
	// structurally valid? The citation check is deliberately not part of
	// that answer — it judges the whole catalog, so a citation that
	// rotted under some other row would block an unrelated flip. The
	// reason text this flip may have added is prose like any other and
	// is judged by the `validate` gate.
	if err := cat2.Validate(ValidationOptions{LenientCrossRefs: false, SkipSymbolCitations: true}); err != nil {
		return restoreAfterFlipFailure(r.File.Path, raw, fmt.Errorf("flip wrote %s but validation failed: %w", r.File.Path, err))
	}
	fmt.Printf("scenariotool: %s %s -> %s\n", id, current, newStatus)
	return nil
}

// restoreAfterFlipFailure puts the original bytes back after a flip
// whose result did not validate, so a failed flip leaves the catalog
// untouched.
func restoreAfterFlipFailure(path string, original []byte, cause error) error {
	if err := os.WriteFile(path, original, 0o600); err != nil { //nolint:gosec // G703: same catalog path that was just written.
		return errors.Join(cause, fmt.Errorf("restore %s: %w", path, err))
	}
	return cause
}

// checkFlipRequest rejects a flip whose target status and reason
// disagree, before anything on disk is touched. A reason is mandatory
// exactly when the target status is out-of-scope, mirroring the catalog
// invariant the post-write validation would otherwise catch only after
// the file was already rewritten.
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

// flipStatusInYAML rewrites the status of one row inside a catalog YAML
// byte slice, together with the exclusion reason that goes with it: the
// reason is written under the status line when flipping to out-of-scope
// and dropped otherwise, because a reason surviving on a row that came
// back in scope would document an exclusion that no longer applies.
//
// The row is located through a yaml.Node tree, so every field is
// replaced or removed by its whole line span (a block scalar's
// continuation lines included). Only those spans are spliced; the rest
// of the file is kept byte for byte, and the result is re-parsed before
// it is returned.
func flipStatusInYAML(raw []byte, id, newStatus, reason string) ([]byte, error) {
	const reasonKey = "out_of_scope_reason"

	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("flipStatusInYAML: parse: %w", err)
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	row, rowEnd, ok := findFlipRow(&doc, id, len(lines))
	if !ok {
		return nil, fmt.Errorf("flipStatusInYAML: row %q not found", id)
	}
	if row.Style&yaml.FlowStyle != 0 {
		return nil, fmt.Errorf("flipStatusInYAML: row %q is written in flow style", id)
	}
	indent := strings.Repeat(" ", row.Content[0].Column-1)

	status := findFlipField(row, lines, rowEnd, "status")
	oldReason := findFlipField(row, lines, rowEnd, reasonKey)
	rowLast := flipFieldEnd(row, lines, rowEnd, len(row.Content)/2-1)

	statusLine := indent + "status: " + newStatus
	reasonLine := indent + reasonKey + ": " + yamlInlineString(reason)
	toOOS := newStatus == "out-of-scope"

	var edits []flipEdit
	if status.found {
		edits = append(edits, flipEdit{status.start, status.end, []string{statusLine}})
		if toOOS && !oldReason.found {
			edits = append(edits, flipEdit{status.end, status.end, []string{reasonLine}})
		}
	} else {
		added := []string{statusLine}
		if toOOS && !oldReason.found {
			added = append(added, reasonLine)
		}
		edits = append(edits, flipEdit{rowLast, rowLast, added})
	}
	if oldReason.found {
		var replacement []string
		if toOOS {
			replacement = []string{reasonLine}
		}
		edits = append(edits, flipEdit{oldReason.start, oldReason.end, replacement})
	}
	sort.SliceStable(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	for _, e := range edits {
		lines = append(lines[:e.start], append(slices.Clone(e.lines), lines[e.end:]...)...)
	}

	out := strings.Join(lines, "\n")
	if len(raw) > 0 && raw[len(raw)-1] == '\n' {
		out += "\n"
	}
	if err := checkFlipResult([]byte(out), id, newStatus, reason, reasonKey); err != nil {
		return nil, err
	}
	return []byte(out), nil
}

// flipEdit replaces lines[start:end) with lines.
type flipEdit struct {
	start, end int
	lines      []string
}

// flipField is the line span [start, end) of one key/value pair inside
// a row.
type flipField struct {
	start, end int
	found      bool
}

// findFlipRow returns the mapping node of the row with the given id and
// the line index where that row ends (the next row, the next top-level
// key, or the end of the file).
func findFlipRow(doc *yaml.Node, id string, nLines int) (*yaml.Node, int, bool) {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, 0, false
	}
	top := doc.Content[0]
	for k := 0; k+1 < len(top.Content); k += 2 {
		if top.Content[k].Value != "rows" || top.Content[k+1].Kind != yaml.SequenceNode {
			continue
		}
		end := nLines
		if k+2 < len(top.Content) {
			end = top.Content[k+2].Line - 1
		}
		items := top.Content[k+1].Content
		for i, item := range items {
			if item.Kind != yaml.MappingNode || len(item.Content) == 0 {
				continue
			}
			rowEnd := end
			if i+1 < len(items) {
				rowEnd = items[i+1].Line - 1
			}
			for j := 0; j+1 < len(item.Content); j += 2 {
				if item.Content[j].Value == "id" && item.Content[j+1].Value == id {
					return item, rowEnd, true
				}
			}
		}
	}
	return nil, 0, false
}

// findFlipField returns the line span of the named key in row.
func findFlipField(row *yaml.Node, lines []string, rowEnd int, key string) flipField {
	for p := 0; p < len(row.Content)/2; p++ {
		if row.Content[2*p].Value == key {
			return flipField{start: row.Content[2*p].Line - 1, end: flipFieldEnd(row, lines, rowEnd, p), found: true}
		}
	}
	return flipField{}
}

// flipFieldEnd returns the exclusive end line of pair p: the line before
// the next pair (or the row), minus trailing blank lines and comments
// that sit at key indentation and so belong to the gap, not the value.
func flipFieldEnd(row *yaml.Node, lines []string, rowEnd, p int) int {
	end := rowEnd
	if 2*p+2 < len(row.Content) {
		end = row.Content[2*p+2].Line - 1
	}
	start := row.Content[2*p].Line - 1
	keyIndent := row.Content[2*p].Column - 1
	for end > start+1 {
		l := lines[end-1]
		trimmed := strings.TrimSpace(l)
		if trimmed != "" && !(strings.HasPrefix(trimmed, "#") && len(l)-len(strings.TrimLeft(l, " ")) <= keyIndent) {
			break
		}
		end--
	}
	return end
}

// checkFlipResult re-parses the edited catalog and confirms the target
// row says what the flip asked for, so a splice that went wrong is
// refused before anything is written.
func checkFlipResult(out []byte, id, newStatus, reason, reasonKey string) error {
	var ff struct {
		Rows []map[string]any `yaml:"rows"`
	}
	if err := yaml.Unmarshal(out, &ff); err != nil {
		return fmt.Errorf("flipStatusInYAML: edited file does not parse: %w", err)
	}
	for _, r := range ff.Rows {
		if r["id"] != id {
			continue
		}
		gotReason, hasReason := r[reasonKey].(string)
		switch {
		case r["status"] != newStatus:
			return fmt.Errorf("flipStatusInYAML: row %q did not take status %q", id, newStatus)
		case newStatus == "out-of-scope" && strings.TrimSpace(gotReason) != strings.TrimSpace(reason):
			return fmt.Errorf("flipStatusInYAML: row %q did not take the reason", id)
		case newStatus != "out-of-scope" && hasReason:
			return fmt.Errorf("flipStatusInYAML: row %q kept a stale reason", id)
		}
		return nil
	}
	return fmt.Errorf("flipStatusInYAML: row %q lost in the edit", id)
}

// yamlInlineString quotes a value safely as a YAML 1.2 double-quoted
// scalar. It is used for exclusion reasons so they may contain
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
