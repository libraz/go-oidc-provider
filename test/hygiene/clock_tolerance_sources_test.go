package hygiene_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Several verification points compare a JWT time claim against the OP's
// clock with a tolerance for skew. Each one is configured separately,
// and the value they settle on is what decides whether a peer whose
// clock is a little off can talk to this OP at all — so two points that
// answer about the same class of token have to take that value from one
// place, not from two literals that happen to read the same today.
//
// "Happen to read the same today" is precisely what an inline literal
// buys: nothing links it to its twin, and nothing fails when one of them
// is edited. So the rule this test enforces is structural rather than
// numeric — every fallback tolerance must resolve to a named constant.
// It deliberately does not assert what the numbers are: the OP runs two
// budgets on purpose (a tighter one for tokens it minted itself, a wider
// one for assertions minted by a peer whose clock it does not control),
// and pinning the values here would freeze that policy in a hygiene
// test instead of in the packages that own it.

// toleranceIdent matches an identifier naming a clock tolerance.
var toleranceIdent = regexp.MustCompile(`(?i)(leeway|skew|tolerance)`)

// durationLiteral matches an inline duration expression — the shape a
// shared source is supposed to replace.
var durationLiteral = regexp.MustCompile(`^\d+ \* time\.(Second|Minute|Millisecond)$`)

// toleranceFallback is one place a zero-valued tolerance is replaced by
// a default.
type toleranceFallback struct {
	// Pos is the repository-relative file:line of the assignment.
	Pos string
	// Ident is the tolerance identifier being filled in.
	Ident string
	// Source is the expression the default comes from.
	Source string
	// Shared reports whether Source names a constant rather than
	// restating a literal.
	Shared bool
}

// TestClockToleranceFallbacksComeFromNamedConstants walks the tree for
// every place a clock tolerance falls back to a default and requires
// that default to be a named constant.
func TestClockToleranceFallbacksComeFromNamedConstants(t *testing.T) {
	t.Parallel()

	found := collectToleranceFallbacks(t, repoRoot(t))
	if len(found) == 0 {
		t.Fatal("no clock-tolerance fallback found anywhere; the walk is broken rather than the tree")
	}

	sort.Slice(found, func(i, j int) bool { return found[i].Pos < found[j].Pos })
	for _, f := range found {
		t.Logf("tolerance fallback %s: %s <- %s (shared=%v)", f.Pos, f.Ident, f.Source, f.Shared)
	}

	for _, f := range found {
		if !f.Shared {
			t.Errorf("%s falls %s back to the inline literal %q instead of a named constant.\n"+
				"Nothing links that number to the other verification points that must agree with it, "+
				"and nothing fails when one of them is edited — which is how two surfaces end up "+
				"disagreeing about whether a clock-skewed peer is acceptable. Give the value a name "+
				"and point every point in its budget at it.",
				f.Pos, f.Ident, f.Source)
		}
	}
}

// collectToleranceFallbacks finds assignments of the shape
//
//	if x <= 0 { x = <default> }
//
// where x names a clock tolerance, plus the equivalent inside a
// composite-literal-free plain assignment guarded by the same test.
func collectToleranceFallbacks(tb testing.TB, root string) []toleranceFallback {
	tb.Helper()

	var out []toleranceFallback
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil //nolint:nilerr // a file the parser cannot read is not evidence; the build catches it.
		}
		ast.Inspect(file, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
				return true
			}
			name := identName(assign.Lhs[0])
			if name == "" || !toleranceIdent.MatchString(name) {
				return true
			}
			src := exprText(assign.Rhs[0])
			if src == "" {
				return true
			}
			// Only defaulting assignments are in scope: a tolerance
			// copied from a caller-supplied field is the wiring this
			// test is checking the far end of, not a source of its own.
			if !isDefaultShaped(src) {
				return true
			}
			out = append(out, toleranceFallback{
				Pos:    rel + ":" + strconv.Itoa(fset.Position(assign.Pos()).Line),
				Ident:  name,
				Source: src,
				Shared: !durationLiteral.MatchString(src),
			})
			return true
		})
		return nil
	})
	if err != nil {
		tb.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// isDefaultShaped reports whether src looks like a default rather than a
// pass-through of a configured value. A selector on a receiver or a
// parameter (v.Leeway, d.Leeway, cfg.Leeway) is the caller's value being
// threaded; a bare identifier, a package-qualified constant, or a
// literal is a default.
func isDefaultShaped(src string) bool {
	if durationLiteral.MatchString(src) {
		return true
	}
	if !strings.Contains(src, ".") {
		return !strings.Contains(src, "(")
	}
	// Package-qualified constants are capitalised after the dot
	// (tokens.DefaultLeeway); a struct field read is not necessarily,
	// so require the receiver to look like a package name.
	parts := strings.SplitN(src, ".", 2)
	recv, sel := parts[0], parts[1]
	if strings.Contains(sel, "(") || strings.Contains(sel, ".") {
		return false
	}
	// A single-letter or short receiver (v, d, c, cfg, deps) is a value,
	// not a package.
	switch recv {
	case "v", "d", "c", "p", "s", "h", "cfg", "deps", "opts", "o":
		return false
	}
	return true
}

// identName returns the identifier text of a simple lvalue.
func identName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	}
	return ""
}

// exprText renders a small expression back to source text. Only the
// shapes a default can take are handled; anything else returns "".
func exprText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		if x := identName(v.X); x != "" {
			return x + "." + v.Sel.Name
		}
		return ""
	case *ast.BinaryExpr:
		l, r := exprText(v.X), exprText(v.Y)
		if l == "" || r == "" {
			return ""
		}
		return l + " " + v.Op.String() + " " + r
	case *ast.BasicLit:
		return v.Value
	}
	return ""
}
