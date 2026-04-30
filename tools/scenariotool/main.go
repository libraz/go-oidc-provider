// scenariotool is the catalog validator and coverage reporter for the
// Spec Scenario Suite. See test/scenarios/catalog/README.md for the
// schema and scripts/scenario.sh for the operator-facing wrapper.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

// usage prints the top-level help text and exits with the supplied
// status code.
func usage(rc int) {
	fmt.Fprintln(os.Stderr, `scenariotool — Spec Scenario Catalog helpers

Usage:
  scenariotool <subcommand> [flags] [args]

Subcommands:
  validate              Schema + cross-file ID uniqueness + cross-ref existence.
  list <feature>        Print rows for one feature file.
  lookup <id>           Resolve one row by ID across every catalog file.
  coverage [--strict]   Diff catalog rows against Test_<PREFIX>_<NNN>_ Go tests.

Flags:
  -dir <path>   Catalog directory (default: test/scenarios/catalog).
  -tests <pkg>  Go test package whose Test_* functions are listed (default: ./test/scenarios/...).`)
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
		if err := fs.Parse(args); err != nil {
			return err
		}
		if fs.NArg() != 1 {
			return fmt.Errorf("lookup: expected exactly one ID argument")
		}
		return runLookup(*dir, fs.Arg(0))

	case "coverage":
		fs := flag.NewFlagSet("coverage", flag.ContinueOnError)
		dir := fs.String("dir", "test/scenarios/catalog", "catalog directory")
		tests := fs.String("tests", "./test/scenarios/...", "go test package selector")
		cwd := fs.String("cwd", "", "working directory for `go test -list` (defaults to current directory)")
		strict := fs.Bool("strict", false, "exit non-zero when any binding gap exists")
		if err := fs.Parse(args); err != nil {
			return err
		}
		return runCoverage(*dir, *tests, *cwd, *strict)

	default:
		return fmt.Errorf("unknown subcommand %q (run scenariotool help)", cmd)
	}
}

// exitError lets handlers signal a structured exit code without
// surfacing as a generic "scenariotool: ..." message.
type exitError struct {
	code    int
	message string
}

func (e *exitError) Error() string { return e.message }
