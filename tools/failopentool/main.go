// Command failopentool reports branches that turn a storage failure
// into a negative answer.
//
// Five audits in a row found the same defect in a different place: a
// store read fails, the caller treats the error as "there is no such
// record", and the request proceeds as though the absent thing were
// genuinely absent. A session lookup that cannot reach the backend
// becomes "not signed in"; a grant lookup that times out becomes "no
// consent"; a delete that failed becomes a success response. Each was
// fixed on its own; nothing stopped the sixth.
//
// The gate is narrow by construction. It reports a branch only when all
// of these hold: the condition is a bare `err != nil`, the error came
// from a storage read, the branch mentions the error nowhere, and the
// branch returns a fabricated negative. A branch that propagates,
// wraps, classifies with errors.Is, or logs the error is deciding about
// the failure and is left alone.
//
// Usage:
//
//	failopentool -root <repo>
package main

import (
	"bufio"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// allowlistPath is where deliberate exceptions live, relative to root.
const allowlistPath = "api/failopen.txt"

// skippedDirs are directories the walk never descends into.
func skippedDirs() map[string]bool {
	return map[string]bool{
		".git": true, "backup": true, "testdata": true, "node_modules": true,
		"vendor": true, "conformance": true,
	}
}

// libraryFile reports whether a repo-relative path is library code. A
// demo or a harness that fabricates a negative is not shipping the
// defect this gate is about.
func libraryFile(path string) bool {
	root := path
	if i := strings.Index(path, "/"); i >= 0 {
		root = path[:i]
	}
	switch root {
	case "examples", "cmd", "sample", "tools", "test":
		return false
	default:
		return true
	}
}

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	if err := run(*root); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(root string) error {
	allowed, err := loadAllowlist(filepath.Join(root, allowlistPath))
	if err != nil {
		return err
	}

	methods, err := loadStoreMethods(root)
	if err != nil {
		return err
	}
	// The interfaces in op/store have declared well over this many
	// (T, error) methods since the gate was written, so a count below
	// it means the parse missed the package, not that the interfaces
	// shrank.
	const minStoreMethods = 15
	if len(methods) < minStoreMethods {
		return fmt.Errorf("failopentool: found %d store read methods (want at least %d): "+
			"the parse is broken, not that the interfaces shrank", len(methods), minStoreMethods)
	}

	findings, scanned, err := scan(root, methods)
	if err != nil {
		return err
	}

	// A gate that scanned nothing reports success. Say so instead.
	const minFiles = 200
	if scanned < minFiles {
		return fmt.Errorf("failopentool: scanned %d library files (want at least %d): the walk is broken, not the tree",
			scanned, minFiles)
	}

	kept := keep(findings, allowed)
	stale := allowed.stale()
	fmt.Printf("failopentool: %d library files scanned, %d allowlisted\n", scanned, len(allowed.rows))
	if len(kept) == 0 && len(stale) == 0 {
		fmt.Println("failopentool: OK")
		return nil
	}
	for _, f := range kept {
		fmt.Fprintln(os.Stderr, "  - "+f.String())
	}
	for _, key := range stale {
		fmt.Fprintf(os.Stderr, "  - %s: allowlisted but nothing here answers negatively any more; drop the row — recorded reason: %s\n",
			key, allowed.rows[key])
	}
	return fmt.Errorf("%d fail-open finding(s), %d stale allowlist row(s)", len(kept), len(stale))
}

// scan walks the library sources under root and returns every finding
// plus how many files were actually read.
func scan(root string, methods map[string]bool) ([]Finding, int, error) {
	var findings []Finding
	scanned := 0
	fset := token.NewFileSet()
	skip := skippedDirs()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		rel, ok := libraryGoFile(root, path, d.Name())
		if !ok {
			return nil
		}
		f, parseErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			return nil //nolint:nilerr // an unparseable file contributes nothing; reporting it is not this gate's job.
		}
		scanned++
		findings = append(findings, Analyze(rel, fset, f, methods)...)
		return nil
	})
	if err != nil {
		return nil, 0, fmt.Errorf("failopentool: walk %q: %w", root, err)
	}
	return findings, scanned, nil
}

// libraryGoFile reports the repo-relative path of a file the gate should
// read, and whether it should be read at all.
func libraryGoFile(root, path, name string) (string, bool) {
	if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
		return "", false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", false
	}
	rel = filepath.ToSlash(rel)
	return rel, libraryFile(rel)
}

// keep drops the allowlisted findings and orders the rest so a failure
// names the same site first on every run.
func keep(findings []Finding, allowed *allowlist) []Finding {
	kept := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if allowed.allows(fmt.Sprintf("%s:%d", f.File, f.Line)) {
			continue
		}
		kept = append(kept, f)
	}
	sort.Slice(kept, func(i, j int) bool {
		if kept[i].File != kept[j].File {
			return kept[i].File < kept[j].File
		}
		return kept[i].Line < kept[j].Line
	})
	return kept
}

// allowlist records the deliberate exceptions to the fail-open check,
// one row per branch's file:line, each carrying a reason.
//
// A row [keep] never consulted is reported as stale rather than left to
// accumulate silently: the allowlist is the record of what the gate is
// deliberately not looking at, and a row whose line moved or whose
// branch was fixed is the gate quietly covering ground nobody
// re-examined.
type allowlist struct {
	rows map[string]string // file:line -> reason
	used map[string]bool
}

// allows reports whether the given file:line is listed, and marks the
// row as consulted so a row nothing matches any more can be told apart
// from one still doing work.
func (a *allowlist) allows(key string) bool {
	if _, ok := a.rows[key]; !ok {
		return false
	}
	a.used[key] = true
	return true
}

// stale returns the file:line of every row [keep] never consulted this
// run, sorted for stable output.
func (a *allowlist) stale() []string {
	var out []string
	for key := range a.rows {
		if !a.used[key] {
			out = append(out, key)
		}
	}
	sort.Strings(out)
	return out
}

// loadAllowlist reads the deliberate exceptions. Each row is
// `<file>:<line> TAB <reason>`; a row without a reason is rejected,
// because an exception nobody had to justify is how this class survives
// a review.
func loadAllowlist(path string) (*allowlist, error) {
	al := &allowlist{rows: map[string]string{}, used: map[string]bool{}}
	f, err := os.Open(path) //nolint:gosec // path is the checked-in allowlist, supplied by the gate wrapper.
	if err != nil {
		if os.IsNotExist(err) {
			return al, nil
		}
		return nil, fmt.Errorf("failopentool: open %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimRight(sc.Text(), " \t")
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		parts := strings.SplitN(text, "\t", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
			return nil, fmt.Errorf("failopentool: %s:%d: row needs '<file>:<line> TAB <reason>'", path, line)
		}
		al.rows[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("failopentool: read %s: %w", path, err)
	}
	return al, nil
}

// writeFile is a thin os.WriteFile wrapper the tests use to build
// allowlist fixtures.
func writeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}
