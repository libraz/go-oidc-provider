package gatekit

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// writeTree writes files (slash path -> body) under a fresh directory.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	return root
}

func TestParseGoFiles_SkipsTestsAndNamedDirs(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"a/a.go":             "package a\n",
		"a/a_test.go":        "package a\n",
		"testdata/x.go":      "package x\n",
		"vendor/v/v.go":      "package v\n",
		"examples/e/e.go":    "package e\n",
		"a/notes.txt":        "not go\n",
		"deep/testdata/y.go": "package y\n",
	})
	var got []string
	err := ParseGoFiles(root, token.NewFileSet(), ParseOptions{
		SkipDirs: SkipDirs("vendor"),
		Mode:     parser.SkipObjectResolution,
	}, func(f File) error {
		got = append(got, f.Rel)
		return nil
	})
	if err != nil {
		t.Fatalf("ParseGoFiles: %v", err)
	}
	sort.Strings(got)
	want := []string{"a/a.go", "examples/e/e.go"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("visited %v, want %v", got, want)
	}
}

func TestParseGoFiles_KeepFiltersBeforeParsing(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"op/op.go":         "package op\n",
		"examples/e.go":    "package broken(\n",
		"cmd/demo/main.go": "package main\n",
	})
	var got []string
	err := ParseGoFiles(root, token.NewFileSet(), ParseOptions{Keep: LibraryFile, Strict: true}, func(f File) error {
		got = append(got, f.Rel)
		return nil
	})
	if err != nil {
		t.Fatalf("ParseGoFiles: %v", err)
	}
	if len(got) != 1 || got[0] != "op/op.go" {
		t.Fatalf("visited %v, want only op/op.go", got)
	}
}

func TestParseGoFiles_ParseFailure(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{
		"ok/ok.go":   "package ok\n",
		"bad/bad.go": "package bad(\n",
	})
	count := func(strict bool) (int, error) {
		n := 0
		err := ParseGoFiles(root, token.NewFileSet(), ParseOptions{Strict: strict}, func(File) error {
			n++
			return nil
		})
		return n, err
	}
	if n, err := count(false); err != nil || n != 1 {
		t.Errorf("lenient: visited %d, err %v; want 1 file and no error", n, err)
	}
	if _, err := count(true); err == nil {
		t.Error("strict: a file that does not parse was accepted")
	}
}

func TestWalkGoFiles_IncludeTests(t *testing.T) {
	t.Parallel()
	root := writeTree(t, map[string]string{"a/a.go": "package a\n", "a/a_test.go": "package a\n"})
	n := 0
	if err := WalkGoFiles(root, nil, true, func(string) error { n++; return nil }); err != nil {
		t.Fatalf("WalkGoFiles: %v", err)
	}
	if n != 2 {
		t.Fatalf("visited %d files, want 2", n)
	}
}

func TestLibraryFile(t *testing.T) {
	t.Parallel()
	for path, want := range map[string]bool{
		"op/op.go":            true,
		"internal/x/x.go":     true,
		"examples/01/main.go": false,
		"cmd/op-demo/main.go": false,
		"tools/x/main.go":     false,
		"test/scenarios/a.go": false,
		"conformance/run.go":  false,
		"main.go":             true,
	} {
		if got := LibraryFile(path); got != want {
			t.Errorf("LibraryFile(%q) = %v, want %v", path, got, want)
		}
	}
}
