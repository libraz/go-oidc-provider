package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// storeDir is where the substore interfaces are declared, relative to
// the repository root.
const storeDir = "op/store"

// loadStoreMethods derives the storage-read method names this gate
// scans for from the op/store interfaces themselves, rather than from a
// hand-maintained guess that drifts out of step with them.
//
// Every exported method declared on an interface in that package whose
// signature returns a value alongside its error — (T, error) — is a
// storage read whose failure this gate must be able to see, independent
// of which interface declares it or when it was added. A method that
// only returns error (a write) never matches this shape and is left
// alone; the gate is about a value standing in for a failure, not about
// mutations.
func loadStoreMethods(root string) (map[string]bool, error) {
	dir := filepath.Join(root, storeDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failopentool: read %s: %w", dir, err)
	}
	out := map[string]bool{}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			return nil, fmt.Errorf("failopentool: parse %s: %w", name, err)
		}
		collectReadMethods(f, out)
	}
	return out, nil
}

// collectReadMethods adds to out every interface method declared in f
// whose signature is shaped (T, error).
func collectReadMethods(f *ast.File, out map[string]bool) {
	for _, d := range f.Decls {
		gen, ok := d.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			if ts, ok := spec.(*ast.TypeSpec); ok {
				collectInterfaceReads(ts, out)
			}
		}
	}
}

// collectInterfaceReads adds the (T, error) methods of ts to out when ts
// declares an interface.
func collectInterfaceReads(ts *ast.TypeSpec, out map[string]bool) {
	iface, ok := ts.Type.(*ast.InterfaceType)
	if !ok || iface.Methods == nil {
		return
	}
	for _, m := range iface.Methods.List {
		fn, ok := m.Type.(*ast.FuncType)
		if !ok || len(m.Names) == 0 || !returnsValueAndError(fn) {
			continue
		}
		out[m.Names[0].Name] = true
	}
}

// returnsValueAndError reports whether a function type's results are
// shaped (T, error): a value alongside the failure this gate is about.
func returnsValueAndError(fn *ast.FuncType) bool {
	results := resultTypes(fn)
	if len(results) != 2 {
		return false
	}
	id, ok := results[1].(*ast.Ident)
	return ok && id.Name == "error"
}

// resultTypes flattens a function type's result fields into one type
// per return value, expanding a field that names several results of
// the same type ("a, b int" is one field naming two results).
func resultTypes(fn *ast.FuncType) []ast.Expr {
	if fn.Results == nil {
		return nil
	}
	var out []ast.Expr
	for _, field := range fn.Results.List {
		n := len(field.Names)
		if n == 0 {
			n = 1
		}
		for range n {
			out = append(out, field.Type)
		}
	}
	return out
}
