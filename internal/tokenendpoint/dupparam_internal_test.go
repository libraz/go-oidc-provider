package tokenendpoint

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestTokenSingleValuedParams_MatchesFormReads derives the set of form
// parameters this package reads as single-valued straight from its own
// source and asserts the duplicate-parameter allow-list covers all of
// them.
//
// The hand-maintained list is the only thing standing between a
// repeated request parameter and RFC 6749 §3.1's prohibition on it, and
// a parameter added to a grant handler without a matching row silently
// resolves to one occurrence instead of being rejected — the exact
// asymmetry an upstream proxy or WAF reading a different occurrence
// exploits. Enumerating the reads by hand in a table would reproduce
// the same failure mode one layer up, so the read set is recovered from
// the AST: any new PostForm.Get call fails this test until the
// allow-list grows a row.
func TestTokenSingleValuedParams_MatchesFormReads(t *testing.T) {
	t.Parallel()

	single, multi := formReads(t)
	if len(single) == 0 {
		t.Fatal("no PostForm.Get reads found; the source scan is broken, not the allow-list")
	}
	for _, name := range single {
		if !slices.Contains(tokenSingleValuedParams, name) {
			t.Errorf("form parameter %q is read via PostForm.Get but is absent from tokenSingleValuedParams: "+
				"a repeated %q would be silently resolved to one occurrence", name, name)
		}
	}

	// The dual direction. A parameter the package reads as a slice is
	// multi-valued by construction, so listing it would reject a wire
	// shape its own RFC permits (RFC 8707 §2 "resource").
	for _, name := range multi {
		if slices.Contains(tokenSingleValuedParams, name) {
			t.Errorf("form parameter %q is read as a slice but appears in tokenSingleValuedParams: "+
				"the gate would reject a legitimately repeated %q", name, name)
		}
	}
}

// formReads scans the package's non-test sources and returns the form
// parameter names read through PostForm.Get (single-valued) and through
// PostForm indexing (multi-valued), each with duplicates collapsed.
func formReads(t *testing.T) (single, multi []string) {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.CallExpr:
				if name, ok := postFormGetArg(node); ok {
					single = appendUnique(single, name)
				}
			case *ast.IndexExpr:
				if name, ok := postFormIndex(node); ok {
					multi = appendUnique(multi, name)
				}
			}
			return true
		})
	}
	return single, multi
}

// postFormGetArg reports the string literal passed to a
// `<expr>.PostForm.Get("name")` call.
func postFormGetArg(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Get" || len(call.Args) != 1 {
		return "", false
	}
	if !isPostForm(sel.X) {
		return "", false
	}
	return stringLit(call.Args[0])
}

// postFormIndex reports the string literal used in a
// `<expr>.PostForm["name"]` index expression.
func postFormIndex(idx *ast.IndexExpr) (string, bool) {
	if !isPostForm(idx.X) {
		return "", false
	}
	return stringLit(idx.Index)
}

// isPostForm reports whether expr selects the PostForm field.
func isPostForm(expr ast.Expr) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "PostForm"
}

// stringLit unquotes expr when it is an untagged string literal.
func stringLit(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

func appendUnique(dst []string, name string) []string {
	if slices.Contains(dst, name) {
		return dst
	}
	return append(dst, name)
}
