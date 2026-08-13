package hygiene_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// op/storeadapter/patterns is a published package path, so a helper in it
// cannot simply be deleted once the tree stops calling it — that is a
// major-version break for anyone who imported it. What can rot instead is
// the package doc, which tells a reader which helpers the in-tree
// adapters share and which are on offer for a backend of their own. A
// helper that quietly loses (or gains) its in-tree callers turns that
// paragraph into a lie, and nothing else in the tree would notice.
//
// So the caller set is derived rather than described: the test records
// which helpers the adapters actually call and fails when the answer
// changes, at which point the doc gets revisited alongside it.

const patternsPkgDir = "op/storeadapter/patterns"

// patternsSharedInTree lists the helpers the in-tree adapters call. The
// package doc names exactly these as "what is actually shared"; the rest
// are documented as available to third-party adapters and are expected
// to have no in-tree caller.
var patternsSharedInTree = map[string]bool{
	"IsExpiredStrict":      true,
	"IsExpiredInclusive":   true,
	"Digest":               true,
	"ConstantTimeKeyMatch": true,
}

// TestPatternsHelperCallersMatchTheDocumentedSplit pins the split the
// package doc describes.
func TestPatternsHelperCallersMatchTheDocumentedSplit(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	exported := patternsExportedFuncs(t, filepath.Join(root, patternsPkgDir))
	if len(exported) == 0 {
		t.Fatalf("no exported helpers found in %s; the extraction is broken rather than the source", patternsPkgDir)
	}
	callers := patternsCallers(t, root, exported)

	for name := range exported {
		called := len(callers[name]) > 0
		switch {
		case patternsSharedInTree[name] && !called:
			t.Errorf("%s is documented as shared by the in-tree adapters but nothing calls it; "+
				"either an adapter stopped using it or the package doc now overstates what is shared",
				name)
		case !patternsSharedInTree[name] && called:
			t.Errorf("%s now has in-tree callers (%s) but the package doc still offers it as a "+
				"third-party helper the tree does not use; move it into the shared list and say so",
				name, strings.Join(callers[name], ", "))
		}
	}
}

// patternsExportedFuncs returns the exported function names the package
// declares.
func patternsExportedFuncs(tb testing.TB, dir string) map[string]bool {
	tb.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		tb.Fatalf("read %s: %v", dir, err)
	}
	out := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			tb.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() {
				continue
			}
			out[fn.Name.Name] = true
		}
	}
	return out
}

// patternsCallers returns, per helper, the repository-relative files that
// call it as patterns.<Name>(...). Test files and the package's own
// sources are excluded: a helper reachable only from its own unit test is
// still one nothing uses.
func patternsCallers(tb testing.TB, root string, exported map[string]bool) map[string][]string {
	tb.Helper()

	out := map[string][]string{}
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
		if strings.HasPrefix(rel, patternsPkgDir) {
			return nil
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// A file the parser cannot read is not evidence of a caller;
			// the build catches a genuinely broken source elsewhere.
			return nil //nolint:nilerr // parse failures are not this test's subject.
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := patternsCallName(call.Fun)
			if !ok || !exported[name] {
				return true
			}
			if !containsString(out[name], rel) {
				out[name] = append(out[name], rel)
			}
			return true
		})
		return nil
	})
	if err != nil {
		tb.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// patternsCallName returns the helper name for a patterns.<Name> call
// expression, including the patterns.Name[T] instantiated form.
func patternsCallName(fun ast.Expr) (string, bool) {
	if idx, ok := fun.(*ast.IndexExpr); ok {
		fun = idx.X
	}
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "patterns" {
		return "", false
	}
	return sel.Sel.Name, true
}
