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
// the row in YAML-like form.
func runLookup(dir, id string) error {
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
	if len(r.CrossRefs) > 0 {
		fmt.Printf("cross_refs: %s\n", strings.Join(r.CrossRefs, ", "))
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
