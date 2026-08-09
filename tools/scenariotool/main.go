// scenariotool is the catalog validator and coverage reporter for the
// Spec Scenario Suite. See test/scenarios/catalog/README.md for the
// schema and scripts/scenario.sh for the operator-facing wrapper.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// usage prints the top-level help text and exits with the supplied
// status code.
func usage(rc int) {
	fmt.Fprintln(os.Stderr, `scenariotool — Spec Scenario Catalog helpers

Usage:
  scenariotool <subcommand> [flags] [args]

Subcommands:
  validate                       Schema + cross-file ID uniqueness + cross-ref existence.
  list <feature>                 Print rows for one feature file.
  lookup <id>                    Resolve one row by ID across every catalog file.
  stats [feature]                Severity x status dashboard, optionally for one feature.
  next [feature]                 Print the next pending row(s) to pick up.
  flip <id> <status>             Update a row's status to active|pending|out-of-scope.
  coverage [--strict|--check-bindings|--yaml-only]
                                 Diff catalog rows against Test_<PREFIX>_<NNN>_ Go tests.
  advisories [--check|--json]    Cross-reference _advisories.yaml with '// Tracks: <id>' comments.

Flags:
  -dir <path>        Catalog directory (default: test/scenarios/catalog).
  -tests <pkg>       Go test package whose Test_* functions are listed (default: ./test/scenarios/...).
  -test-root <path>  Directory holding <feature>_test.go files (default: test/scenarios).
  -source <list>     Comma-separated source roots scanned for '// Tracks:' (advisories; default: internal,op,test).
  -severity P0|P1|P2 Filter (next).
  -count <N>         Cap (next, default 1).
  -reason <text>     Required when flipping to out-of-scope.`)
	os.Exit(rc)
}

func main() {
	if len(os.Args) < 2 {
		usage(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	if cmd == "-h" || cmd == "--help" || cmd == "help" {
		usage(0)
	}

	if err := dispatch(cmd, args); err != nil {
		var ev *exitError
		if errors.As(err, &ev) {
			fmt.Fprintln(os.Stderr, ev.message)
			os.Exit(ev.code)
		}
		fmt.Fprintf(os.Stderr, "scenariotool: %v\n", err)
		os.Exit(1)
	}
}

func dispatch(cmd string, args []string) error {
	switch cmd {
	case "validate":
		fs := flag.NewFlagSet("validate", flag.ContinueOnError)
		dir := fs.String("dir", "test/scenarios/catalog", "catalog directory")
		lenient := fs.Bool("lenient", false, "downgrade dangling cross_ref errors to warnings")
		if err := fs.Parse(args); err != nil {
			return err
		}
		return runValidate(*dir, *lenient)

	case "list":
		fs := flag.NewFlagSet("list", flag.ContinueOnError)
		dir := fs.String("dir", "test/scenarios/catalog", "catalog directory")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return fmt.Errorf("list: expected exactly one feature argument")
		}
		return runList(*dir, fs.Arg(0))

	case "lookup":
		fs := flag.NewFlagSet("lookup", flag.ContinueOnError)
		dir := fs.String("dir", "test/scenarios/catalog", "catalog directory")
		cwd := fs.String("cwd", "", "working directory used to resolve -test-root (defaults to current directory)")
		testRoot := fs.String("test-root", "test/scenarios", "directory holding <feature>_test.go files; pass empty to skip the test_file lookup")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return fmt.Errorf("lookup: expected exactly one ID argument")
		}
		return runLookup(*dir, resolveTestRoot(*cwd, *testRoot), fs.Arg(0))

	case "stats":
		fs := flag.NewFlagSet("stats", flag.ContinueOnError)
		dir := fs.String("dir", "test/scenarios/catalog", "catalog directory")
		if err := fs.Parse(args); err != nil {
			return err
		}
		feature := ""
		if fs.NArg() == 1 {
			feature = fs.Arg(0)
		} else if fs.NArg() > 1 {
			return fmt.Errorf("stats: expected at most one feature argument")
		}
		return runStats(*dir, feature)

	case "next":
		fs := flag.NewFlagSet("next", flag.ContinueOnError)
		dir := fs.String("dir", "test/scenarios/catalog", "catalog directory")
		cwd := fs.String("cwd", "", "working directory used to resolve -test-root")
		testRoot := fs.String("test-root", "test/scenarios", "directory holding <feature>_test.go files")
		severity := fs.String("severity", "", "filter to one severity (P0|P1|P2)")
		count := fs.Int("count", 1, "maximum number of rows to print")
		if err := fs.Parse(args); err != nil {
			return err
		}
		feature := ""
		if fs.NArg() == 1 {
			feature = fs.Arg(0)
		} else if fs.NArg() > 1 {
			return fmt.Errorf("next: expected at most one feature argument")
		}
		return runNext(*dir, resolveTestRoot(*cwd, *testRoot), feature, *severity, *count)

	case "flip":
		fs := flag.NewFlagSet("flip", flag.ContinueOnError)
		dir := fs.String("dir", "test/scenarios/catalog", "catalog directory")
		reason := fs.String("reason", "", "out_of_scope_reason (required when flipping to out-of-scope)")
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() != 2 {
			return fmt.Errorf("flip: expected <id> <status> (status is active|pending|out-of-scope)")
		}
		return runFlip(*dir, fs.Arg(0), fs.Arg(1), *reason)

	case "coverage":
		fs := flag.NewFlagSet("coverage", flag.ContinueOnError)
		dir := fs.String("dir", "test/scenarios/catalog", "catalog directory")
		tests := fs.String("tests", "./test/scenarios/...", "go test package selector")
		cwd := fs.String("cwd", "", "working directory for `go test -list` (defaults to current directory)")
		testRoot := fs.String("test-root", "test/scenarios", "directory holding <feature>_test.go files; pass empty to skip the skip-stub scan")
		strict := fs.Bool("strict", false, "exit non-zero when any binding gap exists, skip-only bindings included")
		checkBindings := fs.Bool("check-bindings", false, "exit non-zero on a row without a test, a test without a row, or a running test under an out-of-scope row")
		yamlOnly := fs.Bool("yaml-only", false, "skip `go test -list` and report only YAML-side counts")
		if err := fs.Parse(args); err != nil {
			return err
		}
		return runCoverage(*dir, *tests, *cwd, resolveTestRoot(*cwd, *testRoot), *strict, *checkBindings, *yamlOnly)

	case "advisories":
		fs := flag.NewFlagSet("advisories", flag.ContinueOnError)
		dir := fs.String("dir", "test/scenarios/catalog", "catalog directory")
		cwd := fs.String("cwd", "", "working directory used to resolve -source roots (defaults to current directory)")
		source := fs.String("source", "internal,op,test", "comma-separated source roots scanned for `// Tracks:` comments")
		check := fs.Bool("check", false, "exit non-zero on drift / orphan / wrong-status")
		asJSON := fs.Bool("json", false, "emit machine-readable JSON instead of the dashboard")
		if err := fs.Parse(args); err != nil {
			return err
		}
		roots := splitNonEmpty(*source, ",")
		if len(roots) == 0 {
			return fmt.Errorf("advisories: -source must list at least one root")
		}
		base := *cwd
		if base == "" {
			wd, err := os.Getwd()
			if err != nil {
				return fmt.Errorf("advisories: getwd: %w", err)
			}
			base = wd
		}
		return runAdvisories(*dir, base, roots, *check, *asJSON)

	default:
		return fmt.Errorf("unknown subcommand %q (run scenariotool help)", cmd)
	}
}

// splitNonEmpty splits s on sep and drops empty / whitespace-only
// fragments. Used by the `advisories` -source flag.
func splitNonEmpty(s, sep string) []string {
	parts := strings.Split(s, sep)
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// resolveTestRoot returns testRoot anchored under cwd when both are
// non-empty and testRoot is relative. The resolution lets the wrapper
// script inject -cwd <repo-root> while command users keep using the
// short relative default.
func resolveTestRoot(cwd, testRoot string) string {
	if testRoot == "" {
		return ""
	}
	if cwd == "" || filepath.IsAbs(testRoot) {
		return testRoot
	}
	return filepath.Join(cwd, testRoot)
}

// exitError lets handlers signal a structured exit code without
// surfacing as a generic "scenariotool: ..." message.
type exitError struct {
	code    int
	message string
}

func (e *exitError) Error() string { return e.message }
