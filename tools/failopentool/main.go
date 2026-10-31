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
	"errors"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/libraz/go-oidc-provider/tools/internal/gatekit"
)

// allowlistPath is where deliberate exceptions live, relative to root.
const allowlistPath = "api/failopen.txt"

// skippedDirs are directories the walk never descends into.
func skippedDirs() map[string]bool {
	return gatekit.SkipDirs("vendor", "conformance")
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
	stale := allowed.Unused()
	fmt.Printf("failopentool: %d library files scanned, %d allowlisted\n", scanned, len(allowed.Rows))
	if len(kept) == 0 && len(stale) == 0 {
		fmt.Println("failopentool: OK")
		return nil
	}
	for _, f := range kept {
		fmt.Fprintln(os.Stderr, "  - "+f.String())
	}
	for _, key := range stale {
		fmt.Fprintf(os.Stderr, "  - %s: allowlisted but nothing here answers negatively any more; drop the row — recorded reason: %s\n",
			key, allowed.Rows[key])
	}
	return fmt.Errorf("%d fail-open finding(s), %d stale allowlist row(s)", len(kept), len(stale))
}

// scan walks the library sources under root and returns every finding
// plus how many files were actually read.
func scan(root string, methods map[string]bool) ([]Finding, int, error) {
	var findings []Finding
	scanned := 0
	fset := token.NewFileSet()
	err := gatekit.ParseGoFiles(root, fset, gatekit.ParseOptions{
		SkipDirs: skippedDirs(),
		Mode:     parser.SkipObjectResolution,
		Keep:     gatekit.LibraryFile,
	}, func(f gatekit.File) error {
		scanned++
		findings = append(findings, Analyze(f.Rel, fset, f.Syntax, methods)...)
		return nil
	})
	if err != nil {
		return nil, 0, fmt.Errorf("failopentool: walk %q: %w", root, err)
	}
	return findings, scanned, nil
}

// keep drops the allowlisted findings and orders the rest so a failure
// names the same site first on every run.
func keep(findings []Finding, allowed *gatekit.Allowlist[string]) []Finding {
	kept := make([]Finding, 0, len(findings))
	for _, f := range findings {
		if allowed.Allows(fmt.Sprintf("%s:%d", f.File, f.Line)) {
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

// loadAllowlist reads the deliberate exceptions, one row per branch's
// file:line, each carrying a reason. Each row is
// `<file>:<line> TAB <reason>`; a row without a reason is rejected,
// because an exception nobody had to justify is how this class survives
// a review.
//
// A row [keep] never consulted is reported as stale rather than left to
// accumulate silently; see [gatekit.Allowlist].
func loadAllowlist(path string) (*gatekit.Allowlist[string], error) {
	al, err := gatekit.LoadAllowlist(path, func(text string) (string, string, error) {
		parts := strings.SplitN(strings.TrimRight(text, " \t"), "\t", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[1]) == "" {
			return "", "", errors.New("row needs '<file>:<line> TAB <reason>'")
		}
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
	})
	if err != nil {
		return nil, fmt.Errorf("failopentool: %w", err)
	}
	return al, nil
}
