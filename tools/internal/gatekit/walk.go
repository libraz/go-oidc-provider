// Package gatekit is the source walk and allowlist loader shared by the
// gate tools. The tools parse sources rather than build them so they
// keep working while the tree is mid-edit; this package is where that
// walk is written down once.
package gatekit

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
)

// SkipDirs returns the directory names a walk never descends into by
// default: version control, the gitignored design-doc tree, and
// fixture and vendored trees that declare nothing a gate reasons about.
// extra adds names for a tool with a further exclusion.
func SkipDirs(extra ...string) map[string]bool {
	skip := map[string]bool{
		".git": true, ".github": true, "backup": true, "node_modules": true, "testdata": true,
	}
	for _, name := range extra {
		skip[name] = true
	}
	return skip
}

// LibraryFile reports whether a repo-relative path is library code: the
// shipping OP itself, not a demo, a harness, or a build tool. A gate
// about what the library does must not be answered by a sample.
func LibraryFile(rel string) bool {
	root := rel
	if i := strings.Index(rel, "/"); i >= 0 {
		root = rel[:i]
	}
	switch root {
	case "examples", "cmd", "sample", "tools", "test", "conformance":
		return false
	default:
		return true
	}
}

// WalkGoFiles calls visit with the path of every .go file under root,
// skipping directories whose base name is in skip. Test files are
// visited only when includeTests is set.
func WalkGoFiles(root string, skip map[string]bool, includeTests bool, visit func(path string) error) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || (!includeTests && strings.HasSuffix(name, "_test.go")) {
			return nil
		}
		return visit(path)
	})
}

// File is one parsed source file.
type File struct {
	// Path is the file's path as walked.
	Path string
	// Rel is the slash-separated path relative to the walk root.
	Rel string
	// Syntax is the parsed file.
	Syntax *ast.File
}

// ParseOptions selects which files [ParseGoFiles] reads and how.
type ParseOptions struct {
	// SkipDirs names the directories the walk never enters.
	SkipDirs map[string]bool
	// Mode is passed to the parser.
	Mode parser.Mode
	// Keep, when set, restricts the walk to the repo-relative paths it
	// accepts; a rejected file is not parsed.
	Keep func(rel string) bool
	// Strict makes a file that does not parse fail the walk. Otherwise
	// such a file contributes nothing, so a tree mid-edit does not turn a
	// gate into a confusing build error.
	Strict bool
}

// ParseGoFiles parses every non-test .go file under root and calls
// visit with each, in walk order.
func ParseGoFiles(root string, fset *token.FileSet, opts ParseOptions, visit func(File) error) error {
	return WalkGoFiles(root, opts.SkipDirs, false, func(path string) error {
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if opts.Keep != nil && !opts.Keep(rel) {
			return nil
		}
		syntax, err := parser.ParseFile(fset, path, nil, opts.Mode)
		if err != nil {
			if opts.Strict {
				return err
			}
			return nil
		}
		return visit(File{Path: path, Rel: rel, Syntax: syntax})
	})
}
