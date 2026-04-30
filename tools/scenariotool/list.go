package main

import (
	"fmt"
	"strings"
)

// runList prints every row in one feature file in tab-separated form
// (id, severity, status, single-line behaviour). The output is meant
// to be human-scannable, not parsed downstream.
func runList(dir, feature string) error {
	cat, err := loadCatalog(dir)
	if err != nil {
		return err
	}
	for _, ff := range cat.Files {
		if ff.Feature == feature {
			fmt.Printf("# %s — %s (%d rows)\n", ff.Feature, ff.Title, len(ff.Rows))
			for _, r := range ff.Rows {
				summary := singleLine(r.Behaviour)
				fmt.Printf("  %s  %s  %-12s  %s\n", r.ID, r.Severity, r.EffectiveStatus(), summary)
			}
			return nil
		}
	}
	return &exitError{code: 1, message: fmt.Sprintf("scenariotool: no catalog file for feature %q", feature)}
}

// runLookup resolves a single ID across every catalog file and prints
// the row in YAML-like form. When testRoot is non-empty the bound
// TestScenario_<ID>_* function (or its absence) is included; cross_refs
// are annotated with the target row's effective status so reviewers
// can see at a glance whether linked rows are also pending.
func runLookup(dir, testRoot, id string) error {
	cat, err := loadCatalog(dir)
	if err != nil {
		return err
	}
	r := cat.Lookup(id)
	if r == nil {
		return &exitError{code: 1, message: fmt.Sprintf("scenariotool: no row with id %q", id)}
	}
	fmt.Printf("file:      %s\n", r.File.Path)
	fmt.Printf("feature:   %s\n", r.File.Feature)
	fmt.Printf("id:        %s\n", r.ID)
	fmt.Printf("severity:  %s\n", r.Severity)
	fmt.Printf("status:    %s\n", r.EffectiveStatus())
	fmt.Printf("spec:      %s\n", singleLine(r.Spec))
	fmt.Printf("behaviour: %s\n", indented(r.Behaviour))
	if testRoot != "" {
		loc, err := locateTest(r, testRoot)
		switch {
		case err != nil:
			fmt.Printf("test_file: %s (locate error: %v)\n", loc.File, err)
		case loc.Found:
			fmt.Printf("test_file: %s:%d\n", loc.File, loc.Line)
		default:
			fmt.Printf("test_file: %s (no TestScenario_<id>_* function yet)\n", loc.File)
		}
	}
	if len(r.CrossRefs) > 0 {
		fmt.Printf("cross_refs: %s\n", strings.Join(crossRefAnnotations(cat, r.CrossRefs), ", "))
	}
	if r.Notes != "" {
		fmt.Printf("notes:     %s\n", indented(r.Notes))
	}
	if r.OutOfScopeReason != "" {
		fmt.Printf("out_of_scope_reason: %s\n", indented(r.OutOfScopeReason))
	}
	return nil
}

// singleLine collapses internal whitespace to one line — useful for
// the summary column produced by `list`.
func singleLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

// indented prefixes every line after the first with two spaces so a
// multi-line `behaviour` block stays aligned under its label.
func indented(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) <= 1 {
		return strings.TrimSpace(s)
	}
	for i := 1; i < len(lines); i++ {
		lines[i] = "           " + lines[i]
	}
	return strings.Join(lines, "\n")
}
