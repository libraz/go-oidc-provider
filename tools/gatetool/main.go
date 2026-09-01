// Command gatetool reconciles the declared gate topology against the
// tree and renders api/gates.md from it.
//
// The project's gates each answer a narrow question, and a green run has
// repeatedly been read as a broader claim than the gate makes: the
// conformance suite passed while a defect lived in three shipped
// multi-account sign-in paths it never routes through, and the example
// harness passed for months without being wired into `make verify`.
// Prose cannot hold that line, because prose drifts. This tool turns the
// claim into something a machine rejects when it stops being true.
//
// Three checks run against the tree:
//
//   - surface-paths: every surface's declared paths still resolve.
//   - makefile: every Makefile target whose recipe runs a script is
//     either claimed as a gate or excused in non_gates, and every
//     declared target still exists.
//   - unexercised: every surface is driven by a gate that runs it, or
//     records why nothing does.
//
// Usage:
//
//	gatetool -root <repo> [-check]   # verify; -check also diffs api/gates.md
//	gatetool -root <repo> -write     # regenerate api/gates.md
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

// mapPath is the source of truth, relative to the repository root.
const mapPath = "test/gates/gates.yaml"

// reportPath is the generated artifact, relative to the repository root.
const reportPath = "api/gates.md"

func main() {
	root := flag.String("root", ".", "repository root")
	write := flag.Bool("write", false, "regenerate "+reportPath)
	check := flag.Bool("check", false, "fail when "+reportPath+" is out of date")
	flag.Parse()

	if err := run(*root, *write, *check); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(root string, write, check bool) error {
	m, err := Load(filepath.Join(root, mapPath))
	if err != nil {
		return err
	}

	findings := Check(root, m)
	rendered := Render(m)
	out := filepath.Join(root, reportPath)

	if write {
		if err := os.WriteFile(out, []byte(rendered), 0o600); err != nil {
			return fmt.Errorf("gatetool: write %s: %w", reportPath, err)
		}
		fmt.Printf("gatetool: wrote %s (%d gates, %d surfaces)\n", reportPath, len(m.Gates), len(m.Surfaces))
	} else if check {
		current, err := os.ReadFile(out) //nolint:gosec // path is the checked-in report, supplied by the gate wrapper.
		if err != nil {
			return fmt.Errorf("gatetool: read %s: %w (run 'make gates-write')", reportPath, err)
		}
		if string(current) != rendered {
			findings = append(findings, Finding{
				Check:   "report",
				Message: reportPath + " is out of date; run 'make gates-write'",
			})
		}
	}

	if len(findings) > 0 {
		for _, f := range findings {
			fmt.Fprintln(os.Stderr, f)
		}
		return fmt.Errorf("gatetool: %d finding(s)", len(findings))
	}

	unexercised := 0
	for _, c := range m.Coverage() {
		if c.Surface.StaticOnlyReason != "" {
			unexercised++
		}
	}
	fmt.Printf("gatetool: OK — %d gates, %d surfaces, %d surface(s) nothing runs\n",
		len(m.Gates), len(m.Surfaces), unexercised)
	return nil
}
