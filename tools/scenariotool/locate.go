package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
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
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, raw, parser.SkipObjectResolution)
	if err != nil {
		return TestLocation{File: file}, fmt.Errorf("parse %s: %w", file, err)
	}
	// The same name-to-ID mapping the coverage gate binds with, so a
	// test is found here exactly when coverage counts it.
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Recv != nil {
			continue
		}
		if id, ok := scenarioIDFromTestName(fd.Name.Name); ok && id == r.ID {
			return TestLocation{File: file, Line: fset.Position(fd.Pos()).Line, Found: true}, nil
		}
	}
	return TestLocation{File: file}, nil
}
