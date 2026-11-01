package hygiene_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The SQL adapter's package overview tells an operator what a single
// GC call reclaims, and that overview is the only place the sweep set
// is described as a whole. Nothing links it to the sweep list itself,
// so a table added to Store.GC leaves the overview describing a
// smaller job than the one that runs — which is how a reader ends up
// sizing a maintenance window against the wrong work. The counts are
// therefore derived from the source rather than restated in prose.

const (
	sqlGCSourceDir   = "op/storeadapter/sql"
	sqlGCSourcePath  = "op/storeadapter/sql/gc.go"
	sqlGCDocPath     = "op/storeadapter/sql/doc.go"
	sqlGCRetentionH  = "# Retention"
	sqlGCStatsStruct = "GCStats"
)

// TestSQLGCSweepsMatchStatsAndOverview pins the three places the sweep
// set is spelled out: the sweep list Store.GC iterates, the per-table
// counters it fills, and the count the package overview quotes.
func TestSQLGCSweepsMatchStatsAndOverview(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join(root, sqlGCSourcePath), nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", sqlGCSourcePath, err)
	}

	counters := gcSweepCounters(t, file)
	if len(counters) == 0 {
		t.Fatalf("%s declares no sweep list; the extraction is broken rather than the source", sqlGCSourcePath)
	}
	fields := gcStatsFields(t, file)

	for _, name := range counters {
		if !fields[name] {
			t.Errorf("Store.GC counts a sweep into %s.%s, which the struct does not declare", sqlGCStatsStruct, name)
		}
	}
	for name := range fields {
		if !slices.Contains(counters, name) {
			t.Errorf("%s.%s is reported to callers but no sweep in Store.GC ever fills it, so it always reads zero",
				sqlGCStatsStruct, name)
		}
	}

	// Every substore that carries a GC method must be swept by Store.GC.
	// The Store fields are matched by type, so a substore added later is
	// caught without anyone listing it here.
	referenced := gcSweepSubstoreRefs(t, file)
	for typeName, field := range gcSubstoreFields(t, filepath.Join(root, sqlGCSourceDir)) {
		if !referenced[field] {
			t.Errorf("%s has a GC method and is held by Store.%s, but the sweep table in Store.GC "+
				"never calls s.%s.GC, so its expired rows are never reclaimed",
				typeName, field, field)
		}
	}

	overview := retentionSection(t, filepath.Join(root, sqlGCDocPath))
	want := "The " + numberWord(t, len(counters)) + " sweeps"
	if !strings.Contains(overview, want) {
		t.Errorf("Store.GC runs %d sweeps but the Retention section of %s does not say %q; "+
			"an operator scheduling the job reads the overview, not the sweep list",
			len(counters), sqlGCDocPath, want)
	}
}

// gcSweepCounters returns, in source order, the GCStats field each
// sweep in Store.GC writes its row count into. The list is read off the
// `&stats.Field` element of every sweep literal, which is the one part
// of the entry that cannot be wrong without the count going somewhere
// else.
func gcSweepCounters(tb testing.TB, file *ast.File) []string {
	tb.Helper()

	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "GC" || fn.Recv == nil {
			return true
		}
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			lit, ok := inner.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if _, isSlice := lit.Type.(*ast.ArrayType); !isSlice {
				return true
			}
			for _, elt := range lit.Elts {
				entry, ok := elt.(*ast.CompositeLit)
				if !ok {
					continue
				}
				if name := statsFieldRef(entry); name != "" {
					out = append(out, name)
				}
			}
			return false
		})
		return false
	})
	return out
}

// gcSweepSubstoreRefs returns the Store field names X for which the sweep
// table in Store.GC mentions `s.X.GC`.
func gcSweepSubstoreRefs(tb testing.TB, file *ast.File) map[string]bool {
	tb.Helper()

	out := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "GC" || fn.Recv == nil {
			return true
		}
		ast.Inspect(fn.Body, func(inner ast.Node) bool {
			lit, ok := inner.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if _, isSlice := lit.Type.(*ast.ArrayType); !isSlice {
				return true
			}
			ast.Inspect(lit, func(elt ast.Node) bool {
				sel, ok := elt.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "GC" {
					return true
				}
				field, ok := sel.X.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if recv, ok := field.X.(*ast.Ident); ok && recv.Name == "s" {
					out[field.Sel.Name] = true
				}
				return true
			})
			return false
		})
		return false
	})
	return out
}

// gcSubstoreFields returns, for every type T (other than Store) with a
// `func (s *T) GC(` method in the adapter's non-test sources, the name
// of the Store struct field of type *T.
func gcSubstoreFields(tb testing.TB, dir string) map[string]string {
	tb.Helper()

	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		tb.Fatalf("glob %s: %v", dir, err)
	}
	receivers := map[string]bool{}
	fieldOf := map[string]string{}
	fset := token.NewFileSet()
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			tb.Fatalf("parse %s: %v", path, err)
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Name.Name != "GC" || d.Recv == nil || len(d.Recv.List) != 1 {
					continue
				}
				if star, ok := d.Recv.List[0].Type.(*ast.StarExpr); ok {
					if id, ok := star.X.(*ast.Ident); ok && id.Name != "Store" {
						receivers[id.Name] = true
					}
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok || ts.Name.Name != "Store" {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok {
						continue
					}
					for _, field := range st.Fields.List {
						star, ok := field.Type.(*ast.StarExpr)
						if !ok {
							continue
						}
						id, ok := star.X.(*ast.Ident)
						if !ok {
							continue
						}
						for _, name := range field.Names {
							fieldOf[id.Name] = name.Name
						}
					}
				}
			}
		}
	}
	if len(receivers) == 0 {
		tb.Fatalf("no substore GC methods found under %s; the extraction is broken rather than the source", dir)
	}
	out := map[string]string{}
	for typeName := range receivers {
		field, ok := fieldOf[typeName]
		if !ok {
			tb.Errorf("%s has a GC method but no *%s field on Store, so Store.GC cannot reach it", typeName, typeName)
			continue
		}
		out[typeName] = field
	}
	return out
}

// statsFieldRef returns the field name of the first `&stats.Field`
// element in a sweep entry, or "" when the entry has none.
func statsFieldRef(entry *ast.CompositeLit) string {
	for _, field := range entry.Elts {
		unary, ok := field.(*ast.UnaryExpr)
		if !ok || unary.Op != token.AND {
			continue
		}
		sel, ok := unary.X.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok || ident.Name != "stats" {
			continue
		}
		return sel.Sel.Name
	}
	return ""
}

// gcStatsFields returns the set of exported field names on GCStats.
func gcStatsFields(tb testing.TB, file *ast.File) map[string]bool {
	tb.Helper()

	out := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok || spec.Name.Name != sqlGCStatsStruct {
			return true
		}
		structType, ok := spec.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, field := range structType.Fields.List {
			for _, name := range field.Names {
				if name.IsExported() {
					out[name.Name] = true
				}
			}
		}
		return false
	})
	if len(out) == 0 {
		tb.Fatalf("no exported fields found on %s; the extraction is broken rather than the source", sqlGCStatsStruct)
	}
	return out
}

// retentionSection returns the text of the package comment's Retention
// heading, up to the next heading.
func retentionSection(tb testing.TB, docPath string) string {
	tb.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, docPath, nil, parser.ParseComments)
	if err != nil {
		tb.Fatalf("parse %s: %v", docPath, err)
	}
	if file.Doc == nil {
		tb.Fatalf("%s carries no package comment", docPath)
	}
	text := file.Doc.Text()
	start := strings.Index(text, sqlGCRetentionH)
	if start < 0 {
		tb.Fatalf("%s has no %q heading", docPath, sqlGCRetentionH)
	}
	rest := text[start+len(sqlGCRetentionH):]
	if end := strings.Index(rest, "\n# "); end >= 0 {
		return rest[:end]
	}
	return rest
}

// numberWord spells a small count the way prose does.
func numberWord(tb testing.TB, n int) string {
	tb.Helper()

	words := []string{"zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"}
	if n < 0 || n >= len(words) {
		tb.Fatalf("no spelling for %d; extend the table alongside the sweep that needed it", n)
	}
	return words[n]
}
