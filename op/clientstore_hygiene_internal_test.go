package op

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rawClientStoreExemptions names the functions allowed to read
// store.Clients() directly. Every other client lookup goes through
// [config.clientStore] so a client ID metadata document client resolves
// at every endpoint.
var rawClientStoreExemptions = map[string]string{
	// The accessor itself and the decorator it wraps around the store.
	"clientStore":      "op_builders.go",
	"buildClientStore": "op_builders.go",
}

// TestClientStoreHygiene_NoRawClientsLookup fails on any `<x>.store.Clients()`
// call in the op package outside [rawClientStoreExemptions]. The DCR
// registry (resolveClientRegistry) is a write-side view and is not a
// Clients() call, so it needs no entry here.
func TestClientStoreHygiene_NoRawClientsLookup(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	fset := token.NewFileSet()
	seen := map[string]bool{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name) //nolint:gosec // G304: reads this package's own source files.
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		file, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if !isRawClientsCall(n) {
					return true
				}
				if want, ok := rawClientStoreExemptions[fn.Name.Name]; ok && want == name {
					seen[fn.Name.Name] = true
					return true
				}
				t.Errorf("%s: %s calls store.Clients() directly; use cfg.clientStore()",
					fset.Position(n.Pos()), fn.Name.Name)
				return true
			})
		}
	}
	// A stale exemption would silently widen the allow-list.
	for fn, file := range rawClientStoreExemptions {
		if !seen[fn] {
			t.Errorf("exemption %s (%s) no longer calls store.Clients(); drop it", fn, file)
		}
	}
}

// isRawClientsCall matches `<x>.store.Clients()`.
func isRawClientsCall(n ast.Node) bool {
	call, ok := n.(*ast.CallExpr)
	if !ok || len(call.Args) != 0 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Clients" {
		return false
	}
	recv, ok := sel.X.(*ast.SelectorExpr)
	return ok && recv.Sel.Name == "store"
}
