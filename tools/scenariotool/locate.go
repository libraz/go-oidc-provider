package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// TestLocation describes where a row's TestScenario_<ID>_* function
// declaration lives on disk. Found is false when the test file exists
// but no matching function declaration was discovered (typically a row
// whose stub has not been created yet, or a row whose function was
// renamed out of the canonical shape).
type TestLocation struct {
	File  string // path of the _test.go file (relative to the operator-supplied test root)
	Line  int    // 1-indexed line of the func declaration; 0 when Found=false
	Found bool
}

// locateTest finds the TestScenario_<ID>_* function for a row. testRoot
// is the directory holding <feature>_test.go files (typically
// test/scenarios). The returned path is testRoot joined with
// <feature>_test.go even when the function is missing or the file does
// not yet exist, so callers can quote it in error messages without
// extra plumbing.
func locateTest(r *Row, testRoot string) (TestLocation, error) {
	file := filepath.Join(testRoot, r.File.Feature+"_test.go")
	raw, err := os.ReadFile(file) //nolint:gosec // testRoot is operator-controlled.
	if err != nil {
		if os.IsNotExist(err) {
			return TestLocation{File: file}, nil
		}
		return TestLocation{File: file}, fmt.Errorf("read %s: %w", file, err)
	}
	underscored := strings.ReplaceAll(r.ID, "-", "_")
	// Match `func TestScenario_<UNDERSCORED>_<Slug>(` and the bare
	// `func Test<UNDERSCORED>_<Slug>(` form. The optional `_<Slug>` is
	// what carries the human-readable suffix.
	needle := regexp.MustCompile(
		`^func Test(?:Scenario_)?` + regexp.QuoteMeta(underscored) + `(?:_[A-Za-z0-9]+)?\(`,
	)
	for i, line := range strings.Split(string(raw), "\n") {
		if needle.MatchString(line) {
			return TestLocation{File: file, Line: i + 1, Found: true}, nil
		}
	}
	return TestLocation{File: file}, nil
}
