package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/libraz/go-oidc-provider/tools/internal/gatekit"
)

// allowlist records the vocabulary that is deliberately unreached.
//
// Every row carries a reason, and the reason has to argue why nothing
// reading the entry is the correct state — reserved wire vocabulary a
// deployment raises itself, a constant that exists so an embedder can
// name it in their own configuration, and so on. "Not got to it yet" is
// not one of those arguments; a row that means that is a row that
// should be a deletion instead.
type allowlist = gatekit.Allowlist[allowRow]

// allowRow is one parsed allowlist entry.
type allowRow struct {
	kind   string
	id     string
	reason string
}

// allowKey addresses a row the way a check looks one up. The kind never
// contains a space, so the first space separates it from the id.
func allowKey(kind, id string) string { return kind + " " + id }

// loadAllowlist reads the tab-separated allowlist. A missing file is an
// empty allowlist rather than an error, so the gate can be run against
// a tree that has not grown one yet.
func loadAllowlist(path string) (*allowlist, error) {
	return gatekit.LoadAllowlist(path, func(text string) (string, allowRow, error) {
		row, err := parseAllowRow(text)
		return allowKey(row.kind, row.id), row, err
	})
}

// parseAllowRow splits one row into its three tab-separated fields.
func parseAllowRow(text string) (allowRow, error) {
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
	return allowRow{kind: kind, id: id, reason: reason}, nil
}

// allowed reports whether an entry is listed, and marks the row as
// having been consulted so an entry the tree has outgrown can be told
// apart from one still doing work.
func allowed(a *allowlist, kind, id string) bool { return a.Allows(allowKey(kind, id)) }

// staleRows returns one finding per row that no check consulted.
//
// A stale row is a failure, not a note. The allowlist is the record of
// what the gate is deliberately not looking at, so a row that stopped
// applying — the symbol was deleted, or something finally started
// reading it — is the gate quietly covering ground nobody re-examined.
// Making it fail is what keeps the list from accumulating the exact
// residue it exists to prevent.
func staleRows(a *allowlist) []finding {
	var out []finding
	for _, key := range a.Unused() {
		row := a.Rows[key]
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
