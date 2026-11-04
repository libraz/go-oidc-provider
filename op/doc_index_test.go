package op_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// exportedFuncsByResult parses the non-test sources of package op and
// groups the exported top-level functions that return a single value by the
// name of that value's type. The "Option" group is the option set; the
// others return a different option-shaped type.
func exportedFuncsByResult(t *testing.T) map[string][]string {
	t.Helper()

	fset := token.NewFileSet()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("list package op: %v", err)
	}
	byResult := map[string][]string{}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() {
				continue
			}
			res := fn.Type.Results
			if res == nil || len(res.List) != 1 {
				continue
			}
			if id, ok := res.List[0].Type.(*ast.Ident); ok {
				byResult[id.Name] = append(byResult[id.Name], fn.Name.Name)
			}
		}
	}
	return byResult
}

// optionGroupsBlock returns the text of the "# Option groups" section of
// op/doc.go, up to the next heading.
func optionGroupsBlock(t *testing.T) string {
	t.Helper()

	raw, err := os.ReadFile("doc.go")
	if err != nil {
		t.Fatalf("read doc.go: %v", err)
	}
	text := string(raw)
	start := strings.Index(text, "// # Option groups")
	if start < 0 {
		t.Fatal("doc.go has no \"# Option groups\" section")
	}
	rest := text[start+len("// # Option groups"):]
	if end := strings.Index(rest, "\n// # "); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

// TestDocOptionGroupsIndexMatchesExportedOptions keeps the "Option groups"
// index in op/doc.go in step with the code: every exported top-level
// function returning [op.Option] is listed there, and every [WithX] entry
// names a function that exists. Constructors returning another
// *Option type may appear in the block but are not required to.
func TestDocOptionGroupsIndexMatchesExportedOptions(t *testing.T) {
	t.Parallel()

	byResult := exportedFuncsByResult(t)
	options := byResult["Option"]
	if len(options) < 50 {
		t.Fatalf("found %d option constructors: the package scan is broken, not the index", len(options))
	}
	var subOptions []string
	for result, names := range byResult {
		if result != "Option" && strings.HasSuffix(result, "Option") {
			subOptions = append(subOptions, names...)
		}
	}

	entry := regexp.MustCompile(`\[(With\w+)\]`)
	indexed := map[string]struct{}{}
	for _, m := range entry.FindAllStringSubmatch(optionGroupsBlock(t), -1) {
		indexed[m[1]] = struct{}{}
	}

	var missing, unknown []string
	for _, name := range options {
		if _, ok := indexed[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range indexed {
		if !slices.Contains(options, name) && !slices.Contains(subOptions, name) {
			unknown = append(unknown, name)
		}
	}
	slices.Sort(missing)
	slices.Sort(unknown)
	if len(missing) > 0 {
		t.Errorf("option constructors missing from the doc.go \"Option groups\" index: %v", missing)
	}
	if len(unknown) > 0 {
		t.Errorf("doc.go \"Option groups\" entries that name no exported option constructor: %v", unknown)
	}
}
