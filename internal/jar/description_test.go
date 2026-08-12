package jar_test

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jar"
)

// TestDescription_CoversEverySentinel is the gate that keeps the
// catalogue from falling behind the errors it describes.
//
// The three endpoints that render a JAR failure each carried their own
// copy of this table, and the copies drifted: one grew a row the others
// never got, and no copy ever gained one for [jar.ErrTypeInvalid], so
// that failure rendered as the generic fallback everywhere. Sharing the
// table removes the drift between endpoints but not the drift between
// the table and the sentinel list — a new sentinel still silently
// resolves to the fallback.
//
// The test closes that by reading both files rather than restating
// either: the sentinel names come from the var block in error.go, the
// covered names from the composite literal in description.go, and the
// two sets must be equal. Adding a sentinel without a description fails
// here, and so does leaving a row behind for a sentinel that was
// removed.
func TestDescription_CoversEverySentinel(t *testing.T) {
	t.Parallel()

	declared := sentinelNames(t, "error.go")
	if len(declared) == 0 {
		t.Fatal("no sentinels parsed out of error.go; the test is not measuring anything")
	}
	described := describedNames(t, "description.go")

	for name := range declared {
		if !described[name] {
			t.Errorf("%s has no row in the description catalogue; it would render as the generic fallback", name)
		}
	}
	for name := range described {
		if !declared[name] {
			t.Errorf("the description catalogue has a row for %s, which error.go does not declare", name)
		}
	}
}

// TestDescription_PrefersTheSpecificCauseOverParse pins the ordering
// contract the catalogue depends on. The verifier reports a specific
// failure by wrapping it around [jar.ErrParse], so a catalogue walked in
// the wrong order would resolve every such error to "malformed" and
// hide the cause the operator needs.
func TestDescription_PrefersTheSpecificCauseOverParse(t *testing.T) {
	t.Parallel()

	wrapped := fmt.Errorf("%w: %w", jar.ErrSigInvalid, jar.ErrParse)
	if !errors.Is(wrapped, jar.ErrParse) {
		t.Fatal("fixture does not unwrap onto ErrParse; the ordering hazard is not being exercised")
	}
	got := jar.Description(wrapped)
	if got == jar.Description(jar.ErrParse) {
		t.Fatalf("Description resolved a wrapped signature failure to the parse description: %q", got)
	}
	if want := jar.Description(jar.ErrSigInvalid); got != want {
		t.Errorf("Description = %q, want %q", got, want)
	}
}

// TestDescription_FallsBackForAnUnknownError keeps the function total:
// callers render the result unconditionally, so an error from outside
// the catalogue must still produce a description rather than an empty
// string.
func TestDescription_FallsBackForAnUnknownError(t *testing.T) {
	t.Parallel()

	got := jar.Description(errors.New("something else entirely"))
	if got == "" {
		t.Fatal("Description returned an empty string for an unknown error")
	}
	if strings.Contains(got, "something else entirely") {
		t.Errorf("Description echoed the wrapped cause: %q", got)
	}
}

// sentinelNames returns the names of the package-level error values
// declared in file. It recognises a sentinel by its declaration shape —
// an Err-prefixed identifier bound to a call — so the set tracks the
// source rather than a list maintained alongside it.
func sentinelNames(tb testing.TB, file string) map[string]bool {
	tb.Helper()

	names := map[string]bool{}
	for _, spec := range varSpecs(tb, file) {
		for i, ident := range spec.Names {
			if !strings.HasPrefix(ident.Name, "Err") || i >= len(spec.Values) {
				continue
			}
			if _, ok := spec.Values[i].(*ast.CallExpr); ok {
				names[ident.Name] = true
			}
		}
	}
	return names
}

// describedNames returns the sentinel identifiers the catalogue in file
// carries a row for. Rows are composite literals whose first element
// names the sentinel.
func describedNames(tb testing.TB, file string) map[string]bool {
	tb.Helper()

	names := map[string]bool{}
	for _, spec := range varSpecs(tb, file) {
		for _, value := range spec.Values {
			outer, ok := value.(*ast.CompositeLit)
			if !ok {
				continue
			}
			for _, row := range outer.Elts {
				lit, ok := row.(*ast.CompositeLit)
				if !ok || len(lit.Elts) == 0 {
					continue
				}
				if ident, ok := lit.Elts[0].(*ast.Ident); ok {
					names[ident.Name] = true
				}
			}
		}
	}
	return names
}

// varSpecs parses file and returns every package-level var spec in it.
func varSpecs(tb testing.TB, file string) []*ast.ValueSpec {
	tb.Helper()

	parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.SkipObjectResolution)
	if err != nil {
		tb.Fatalf("parse %s: %v", file, err)
	}
	var specs []*ast.ValueSpec
	for _, decl := range parsed.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			if v, ok := spec.(*ast.ValueSpec); ok {
				specs = append(specs, v)
			}
		}
	}
	return specs
}
