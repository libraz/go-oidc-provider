// Package hygiene_test holds checks over the repository's own sources
// rather than over the library's behaviour. They exist because some
// mistakes are invisible to a passing test suite: the suite is green
// today and fails on a date nobody chose.
package hygiene_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// horizonYears is how far ahead a future-dated literal has to sit to
// count as "not a deadline". It is deliberately longer than any
// plausible maintenance life of this repository: the point is that no
// future reader ever has to renew the value, because a fixture that
// must be renewed is a fixture that will one day fail instead.
const horizonYears = 50

// isoDatePrefix matches a string literal that opens with an ISO-8601
// calendar date, which is how a timestamp reaches a fixture when it is
// not written as a [time.Date] call.
var isoDatePrefix = regexp.MustCompile(`^(\d{4})-\d{2}-\d{2}`)

// skippedDirs are trees the check does not walk. Generated and
// vendored code is not ours to date, and backup/ is local working
// material that never reaches a clone.
var skippedDirs = map[string]bool{
	".git":     true,
	"backup":   true,
	"vendor":   true,
	"testdata": true,
}

// TestNoExpiringDateLiterals fails on a source literal that dates a
// fixture into the near future.
//
// A date literal in a test is one of two things. Either it pins the
// clock the code under test reads, in which case it is at or before
// today and stays valid forever because the test never consults the
// wall clock; or it is a horizon — a certificate NotAfter, a token
// exp, a cache deadline — that the wall clock will eventually cross.
// The second kind passes review, passes CI, and then fails on its
// expiry date, usually in a package nobody has touched in years.
//
// The check reads that distinction off the year alone: a literal dated
// past the current year is a horizon, and a horizon has to sit beyond
// [horizonYears] so it can never arrive. Anything in between is the
// shape that turns into a scheduled failure.
//
// The rule ages correctly on its own. Pinned clock values fall further
// into the past every year and are never flagged again, while a
// horizon written today is measured against the year the check runs
// in, not against the year it was written.
func TestNoExpiringDateLiterals(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	// The comparison uses the real wall clock deliberately: the whole
	// question is what today's date does to these literals.
	now := time.Now().UTC().Year()
	required := now + horizonYears

	var findings []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		years, ferr := datedLiterals(path)
		if ferr != nil {
			return ferr
		}
		for _, y := range years {
			// The band is left-closed at the current year: a literal
			// dated to next year is the archetypal one-year horizon (a
			// certificate NotAfter, a one-year token exp), and exempting
			// it left exactly that shape permanently invisible. Only a
			// year at or before the one the check runs in is safe,
			// because it can never move back into the future.
			if y.year <= now || y.year >= required {
				continue
			}
			rel, rerr := filepath.Rel(root, path)
			if rerr != nil {
				rel = path
			}
			findings = append(findings, fmt.Sprintf("%s:%d: %s dates a fixture to %d", rel, y.line, y.text, y.year))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}

	if len(findings) > 0 {
		t.Errorf("%d fixture(s) expire before %d.\n"+
			"A date this close to the present is a deadline: the suite passes until the day it arrives.\n"+
			"Move the horizon past %d, or derive it from the clock the test already pins.\n\t%s",
			len(findings), required, required, strings.Join(findings, "\n\t"))
	}
}

// datedYear is one absolute-year literal and where it was written.
type datedYear struct {
	year int
	line int
	text string
}

// datedLiterals reports every absolute year a Go file states, in
// either of the two forms a timestamp takes in this repository: a
// [time.Date] call, or a string that opens with an ISO-8601 date.
func datedLiterals(path string) ([]datedYear, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	var out []datedYear
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			if year, ok := timeDateYear(node); ok {
				out = append(out, datedYear{year: year, line: fset.Position(node.Pos()).Line, text: "time.Date"})
			}
		case *ast.BasicLit:
			if node.Kind != token.STRING {
				return true
			}
			value, uerr := strconv.Unquote(node.Value)
			if uerr != nil {
				return true
			}
			m := isoDatePrefix.FindStringSubmatch(value)
			if m == nil {
				return true
			}
			year, cerr := strconv.Atoi(m[1])
			if cerr != nil {
				return true
			}
			out = append(out, datedYear{year: year, line: fset.Position(node.Pos()).Line, text: strconv.Quote(value)})
		}
		return true
	})
	return out, nil
}

// timeDateYear returns the year argument of a time.Date call written
// with a literal year. Calls that compute the year from a variable are
// not reported: they are already relative to something, which is the
// shape this check is asking for.
func timeDateYear(call *ast.CallExpr) (int, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Date" {
		return 0, false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "time" {
		return 0, false
	}
	if len(call.Args) == 0 {
		return 0, false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return 0, false
	}
	year, err := strconv.Atoi(lit.Value)
	if err != nil {
		return 0, false
	}
	return year, true
}

// repoRoot walks up from the test's working directory to the nearest
// enclosing go.mod. Nothing between this package and the repository
// root declares a module of its own, so the first one found is the
// root module and therefore the top of the tree to scan.
func repoRoot(tb testing.TB) string {
	tb.Helper()
	dir, err := os.Getwd()
	if err != nil {
		tb.Fatalf("getwd: %v", err)
	}
	for {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			tb.Fatalf("no go.mod found above %s", dir)
			return ""
		}
		dir = parent
	}
}
