package hygiene_test

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// A directory with its own go.mod is not a package of the root module,
// so `go run ./that/dir` fails from the repository root — and it fails
// for the reader before it fails for the maintainer, because the
// workspace file that papers over the split is generated and ignored,
// so a clean clone has none. A documented command that only works in a
// tree somebody has already built in is a command that greets every
// newcomer with an error, which is why the shape is checked rather than
// trusted.

// goCommand matches an invocation of the Go tool with a subcommand that
// takes package paths.
var goCommand = regexp.MustCompile(`\bgo\s+(build|install|list|run|test|vet)\b`)

// commandTextFiles are the extensions a runnable command is written in
// — documentation, shell, and the godoc comments that carry an
// example's own quick start. Extensionless files are matched by name
// below.
var commandTextFiles = map[string]bool{
	".go":   true,
	".md":   true,
	".sh":   true,
	".yml":  true,
	".yaml": true,
}

// TestNoRootModulePathsIntoNestedModules fails when a command a reader
// is told to run names a nested module through a root-module package
// path.
//
// The set of nested modules is read off the tree rather than listed
// here, so a module split out later is covered the day it appears —
// which is the moment its quick start is most likely to be written in
// the shape that no longer resolves.
//
// The scope is what a reader runs: README and docs prose, shell under
// scripts/, the Makefile, and the package doc comments examples carry
// their own quick start in. Maintainer tooling under .claude/ is left
// out — it drives a working tree that has been built in, not a fresh
// clone, and it is addressed to an agent rather than to a reader
// following the project's documentation.
func TestNoRootModulePathsIntoNestedModules(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	nested := nestedModuleDirs(t, root)
	if len(nested) == 0 {
		t.Fatal("the scan found no nested module; the repository splits its examples and its demo binary out, so finding none means the walk is broken")
	}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if d.IsDir() {
			if skippedDirs[d.Name()] || d.Name() == ".claude" {
				return fs.SkipDir
			}
			return nil
		}
		if !commandTextFiles[filepath.Ext(d.Name())] && d.Name() != "Makefile" && d.Name() != "Dockerfile" {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		body, rerr := os.ReadFile(filepath.Clean(path)) //nolint:gosec // path comes from a walk of the repository.
		if rerr != nil {
			return rerr
		}
		for i, line := range strings.Split(string(body), "\n") {
			if !goCommand.MatchString(line) {
				continue
			}
			for _, dir := range nested {
				if !strings.Contains(line, "./"+dir) {
					continue
				}
				t.Errorf("%s:%d drives %s through a root-module package path.\n"+
					"%s carries its own go.mod, so the root module does not contain it and the command fails in a clone that has no workspace file.\n"+
					"Run it from the module instead: (cd %s && GOWORK=off go ... .)",
					rel, i+1, dir, dir, dir)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
}

// nestedModuleDirs returns every repository-relative directory below
// the root that declares a module of its own.
func nestedModuleDirs(tb testing.TB, root string) []string {
	tb.Helper()

	var dirs []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if !d.IsDir() {
			return nil
		}
		if skippedDirs[d.Name()] {
			return fs.SkipDir
		}
		if path == root {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		if !declaresModule(root, rel) {
			return nil
		}
		dirs = append(dirs, rel)
		return nil
	})
	if err != nil {
		tb.Fatalf("walk %s: %v", root, err)
	}
	return dirs
}

// declaresModule reports whether the repository-relative directory dir
// holds a go.mod of its own.
func declaresModule(root, dir string) bool {
	_, err := fs.Stat(os.DirFS(root), path.Join(dir, "go.mod"))
	return err == nil
}
