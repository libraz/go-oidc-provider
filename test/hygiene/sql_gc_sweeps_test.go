package hygiene_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
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
		if !containsString(counters, name) {
			t.Errorf("%s.%s is reported to callers but no sweep in Store.GC ever fills it, so it always reads zero",
				sqlGCStatsStruct, name)
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

// containsString reports whether haystack holds needle.
func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
