package gatekit

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Allowlist records a gate's deliberate exceptions, keyed by whatever
// identifies one finding to that gate, and remembers which rows a run
// consulted.
//
// A row nothing consulted is stale: the allowlist is the record of what
// the gate is deliberately not looking at, so a row whose subject moved
// or was fixed is the gate quietly covering ground nobody re-examined.
type Allowlist[R any] struct {
	// Rows maps a finding's key to its parsed row.
	Rows map[string]R
	used map[string]bool
}

// Allows reports whether key is listed, and marks the row consulted.
func (a *Allowlist[R]) Allows(key string) bool {
	if _, ok := a.Rows[key]; !ok {
		return false
	}
	a.used[key] = true
	return true
}

// Unused returns the key of every row no [Allowlist.Allows] call
// matched, sorted for stable output.
func (a *Allowlist[R]) Unused() []string {
	var out []string
	for key := range a.Rows {
		if !a.used[key] {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// LoadAllowlist reads the allowlist at path. Blank lines and lines
// starting with "#" are skipped; every other line, with only its
// trailing CR removed so an empty trailing field survives, goes to
// parse, which returns the row's key and value or rejects it. A key
// listed twice is rejected. A missing file is an empty allowlist, so a
// gate can run against a tree that has not grown one yet.
func LoadAllowlist[R any](path string, parse func(text string) (key string, row R, err error)) (*Allowlist[R], error) {
	al := &Allowlist[R]{Rows: map[string]R{}, used: map[string]bool{}}
	f, err := os.Open(path) //nolint:gosec // path is the checked-in allowlist, supplied by the gate wrapper.
	if err != nil {
		if os.IsNotExist(err) {
			return al, nil
		}
		return nil, fmt.Errorf("open allowlist %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	lines := map[string]int{}
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimRight(sc.Text(), "\r")
		if trimmed := strings.TrimSpace(text); trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, row, err := parse(text)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, line, err)
		}
		if prev, dup := lines[key]; dup {
			return nil, fmt.Errorf("%s:%d: %s is already listed on line %d", path, line, key, prev)
		}
		lines[key] = line
		al.Rows[key] = row
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read allowlist %q: %w", path, err)
	}
	return al, nil
}
