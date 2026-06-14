//nolint:testpackage // test references unexported forbiddenSelector helper.
package oidcsql

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestQueriesIsSoleSQLBuilder is Layer 5 of the SQL-injection
// defence: it walks every .go source file in the package and asserts
// that no file other than queries.go uses string concatenation against
// a [nameMap] field.
//
// The check is structural — it parses the AST rather than grepping —
// so renaming a substore or reordering operands cannot bypass it. A
// future change that interpolates a table name outside queries.go
// fails this test before it can ship.
//
// Allowed locations:
//   - queries.go  : assembles SQL templates (the entire point)
//   - identifier.go : reads fields to drive schema-string rewriting via
//     [strings.ReplaceAll]; not a SQL build site, but the AST shape
//     happens to mirror buildQueries so the file is allow-listed.
func TestQueriesIsSoleSQLBuilder(t *testing.T) {
	t.Parallel()

	allowed := map[string]bool{
		"queries.go":    true,
		"identifier.go": true,
	}

	nameMapFields := nameMapFieldSet(t)

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		if allowed[name] {
			continue
		}
		path := filepath.Join(".", name)
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			bin, ok := n.(*ast.BinaryExpr)
			if !ok {
				return true
			}
			if bin.Op != token.ADD {
				return true
			}
			if forbiddenSelector(bin.X, nameMapFields) {
				pos := fset.Position(bin.Pos())
				t.Errorf("%s:%d: SQL string concatenation against nameMap field — move to queries.go", pos.Filename, pos.Line)
			}
			if forbiddenSelector(bin.Y, nameMapFields) {
				pos := fset.Position(bin.Pos())
				t.Errorf("%s:%d: SQL string concatenation against nameMap field — move to queries.go", pos.Filename, pos.Line)
			}
			return true
		})
	}
}

func nameMapFieldSet(t *testing.T) map[string]bool {
	t.Helper()
	typ := reflect.TypeOf(nameMap{})
	fields := make(map[string]bool, typ.NumField())
	for i := range typ.NumField() {
		fields[typ.Field(i).Name] = true
	}
	if len(fields) != len(defaultNames().all()) {
		t.Fatalf("nameMap field count=%d, defaultNames().all()=%d", len(fields), len(defaultNames().all()))
	}
	return fields
}

// TestForbiddenSelector_DetectsConcatenation feeds the [forbiddenSelector]
// helper a synthetic AST containing the exact pattern Layer 5 is meant
// to catch. If the detector itself regresses, this test surfaces the
// regression independent of the package's actual sources.
func TestForbiddenSelector_DetectsConcatenation(t *testing.T) {
	t.Parallel()
	fields := map[string]bool{"refreshes": true, "clients": true}
	cases := []struct {
		name      string
		src       string
		mustCatch bool
	}{
		{
			name: "parent-names-field concat",
			src: `package x
func f(s S) string {
    return "INSERT INTO " + s.parent.names.refreshes + " VALUES"
}`,
			mustCatch: true,
		},
		{
			name: "direct names-field concat",
			src: `package x
func f(n NameMap) string {
    return "DELETE FROM " + n.clients + " WHERE id = ?"
}`,
			mustCatch: true,
		},
		{
			// The aggressive detector flags this too — that is by
			// design (see [forbiddenSelector] doc comment): any
			// future struct that shares a field name with nameMap
			// and gets concatenated should hit a review gate before
			// shipping. Within the package's actual sources no such
			// collision exists.
			name: "unrelated struct field with same name (over-strict by design)",
			src: `package x
type unrelated struct{ refreshes string }
func f(u unrelated) string {
    return "x" + u.refreshes
}`,
			mustCatch: true,
		},
		{
			name: "no-concat reference is fine",
			src: `package x
func f(s S) string {
    return s.parent.names.refreshes
}`,
			mustCatch: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "synth.go", c.src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			caught := false
			ast.Inspect(file, func(n ast.Node) bool {
				bin, ok := n.(*ast.BinaryExpr)
				if !ok || bin.Op != token.ADD {
					return true
				}
				if forbiddenSelector(bin.X, fields) || forbiddenSelector(bin.Y, fields) {
					caught = true
				}
				return true
			})
			if caught != c.mustCatch {
				t.Errorf("caught=%v, want %v\nsrc:%s", caught, c.mustCatch, c.src)
			}
		})
	}
}

// forbiddenSelector reports whether expr is a SelectorExpr whose
// trailing field name is one of nameMapFields. The check is
// deliberately aggressive: any `<expr>.<nameMapField>` access inside a
// string-concatenation BinaryExpr is flagged regardless of the
// receiver type. The reasoning is twofold:
//
//  1. Within this package, no unrelated struct shares a field name
//     with nameMap _and_ uses that field in string concatenation, so
//     the aggressive policy has zero false positives in practice.
//  2. A hypothetical future struct that *did* share a name and want
//     to be concatenated would be exactly the kind of change that
//     should hit a review gate before shipping.
//
// If a legitimate need ever arises, allow-list the offending file via
// TestQueriesIsSoleSQLBuilder rather than weakening this detector.
func forbiddenSelector(expr ast.Expr, nameMapFields map[string]bool) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return nameMapFields[sel.Sel.Name]
}
