package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// allowlist records the vocabulary that is deliberately unreached.
//
// Every row carries a reason, and the reason has to argue why nothing
// reading the entry is the correct state — reserved wire vocabulary a
// deployment raises itself, a constant that exists so an embedder can
// name it in their own configuration, and so on. "Not got to it yet" is
// not one of those arguments; a row that means that is a row that
// should be a deletion instead.
type allowlist struct {
	rows map[string]allowRow
	used map[string]bool
}

// allowRow is one parsed allowlist entry.
type allowRow struct {
	kind   string
	id     string
	reason string
	line   int
}

// key addresses a row the way a check looks one up.
func allowKey(kind, id string) string { return kind + "\x00" + id }

// loadAllowlist reads the tab-separated allowlist. A missing file is an
// empty allowlist rather than an error, so the gate can be run against
// a tree that has not grown one yet.
func loadAllowlist(path string) (*allowlist, error) {
	al := &allowlist{rows: map[string]allowRow{}, used: map[string]bool{}}
	//nolint:gosec // the path is a build flag, not request input.
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return al, nil
		}
		return nil, fmt.Errorf("open allowlist %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		// Trimmed only for the blank / comment test: trimming the row
		// itself would eat the tab that separates an empty reason from
		// the id, and report the row as malformed instead of unargued.
		text := strings.TrimRight(sc.Text(), "\r")
		if trimmed := strings.TrimSpace(text); trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		row, err := parseAllowRow(text, line)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		key := allowKey(row.kind, row.id)
		if prev, dup := al.rows[key]; dup {
			return nil, fmt.Errorf("%s:%d: %s %s is already listed on line %d", path, line, row.kind, row.id, prev.line)
		}
		al.rows[key] = row
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read allowlist %q: %w", path, err)
	}
	return al, nil
}

// parseAllowRow splits one row into its three tab-separated fields.
func parseAllowRow(text string, line int) (allowRow, error) {
	fields := strings.Split(text, "\t")
	if len(fields) != 3 {
		return allowRow{}, fmt.Errorf("want three tab-separated fields (kind, id, reason), got %d", len(fields))
	}
	kind := strings.TrimSpace(fields[0])
	id := strings.TrimSpace(fields[1])
	reason := strings.TrimSpace(fields[2])
	if !validKinds()[kind] {
		return allowRow{}, fmt.Errorf("unknown kind %q; want one of %s", kind, strings.Join(sortedKinds(), ", "))
	}
	if id == "" {
		return allowRow{}, errors.New("empty id")
	}
	if reason == "" {
		return allowRow{}, fmt.Errorf("empty reason; say in one line why nothing reading %s is correct", id)
	}
	return allowRow{kind: kind, id: id, reason: reason, line: line}, nil
}

// allows reports whether an entry is listed, and marks the row as
// having been consulted so an entry the tree has outgrown can be told
// apart from one still doing work.
func (a *allowlist) allows(kind, id string) bool {
	key := allowKey(kind, id)
	if _, ok := a.rows[key]; !ok {
		return false
	}
	a.used[key] = true
	return true
}

// stale returns one finding per row that no check consulted.
//
// A stale row is a failure, not a note. The allowlist is the record of
// what the gate is deliberately not looking at, so a row that stopped
// applying — the symbol was deleted, or something finally started
// reading it — is the gate quietly covering ground nobody re-examined.
// Making it fail is what keeps the list from accumulating the exact
// residue it exists to prevent.
func (a *allowlist) stale() []finding {
	var out []finding
	for key, row := range a.rows {
		if a.used[key] {
			continue
		}
		out = append(out, finding{
			kind: row.kind,
			id:   row.id,
			detail: fmt.Sprintf("allowlisted but no longer unreached (or no longer declared); "+
				"drop the row — recorded reason: %s", row.reason),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].id < out[j].id })
	return out
}

// validKinds is the closed set of allowlist kinds, one per check.
func validKinds() map[string]bool {
	return map[string]bool{
		kindSymbol:  true,
		kindEvent:   true,
		kindMessage: true,
		kindIndex:   true,
		kindConsult: true,
	}
}

// sortedKinds lists the valid kinds for an error message.
func sortedKinds() []string {
	kinds := make([]string, 0, len(validKinds()))
	for k := range validKinds() {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	return kinds
}
