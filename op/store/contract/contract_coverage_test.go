package contract //nolint:testpackage // reads the unexported interface registry it exists to check.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// storePackageDir is the directory holding the interface declarations
// the registry mirrors. The harness lives one level below it.
const storePackageDir = ".."

// TestStoreInterfaceRegistryIsComplete pins allStoreInterfaces against
// the declarations it claims to mirror.
//
// The registry is what makes the single-winner surface derived: the scan
// walks it, so an interface missing from it has its conditional writes
// excused without anyone noticing. Reading the declarations out of the
// package source is the only check that cannot itself go stale — a
// hand-kept list of "interfaces we remembered" would reproduce exactly
// the failure mode the derivation exists to remove.
func TestStoreInterfaceRegistryIsComplete(t *testing.T) {
	t.Parallel()

	declared := declaredStoreInterfaces(t)
	registered := make([]string, 0, len(allStoreInterfaces))
	for _, iface := range allStoreInterfaces {
		if iface.Kind() != reflect.Interface {
			t.Fatalf("allStoreInterfaces holds %s, which is not an interface type", iface)
		}
		registered = append(registered, iface.Name())
	}
	slices.Sort(registered)

	for _, name := range declared {
		if !slices.Contains(registered, name) {
			t.Errorf("store.%s is declared but missing from allStoreInterfaces: its conditional writes "+
				"are excluded from the single-winner surface, so a backend may implement them "+
				"non-atomically and still pass the suite", name)
		}
	}
	for _, name := range registered {
		if !slices.Contains(declared, name) {
			t.Errorf("allStoreInterfaces names store.%s, which the package no longer declares", name)
		}
	}
}

// declaredStoreInterfaces reports every exported interface type the
// store package declares, read from its source.
func declaredStoreInterfaces(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(storePackageDir)
	if err != nil {
		t.Fatalf("read store package dir: %v", err)
	}
	fset := token.NewFileSet()
	var names []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(storePackageDir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		names = append(names, exportedInterfaceNames(file)...)
	}
	if len(names) == 0 {
		t.Fatal("no interface declarations found in the store package: the parse found nothing to compare against")
	}
	slices.Sort(names)
	return names
}

func exportedInterfaceNames(file *ast.File) []string {
	var names []string
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.TYPE {
			continue
		}
		for _, spec := range gen.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || !ts.Name.IsExported() {
				continue
			}
			if _, ok := ts.Type.(*ast.InterfaceType); ok {
				names = append(names, ts.Name.Name)
			}
		}
	}
	return names
}
