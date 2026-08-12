package main

import (
	"fmt"
	"sort"
	"strings"
)

// pendingCandidate is one pending row plus its severity rank, kept
// alongside the row so the ordering does not have to re-derive it.
type pendingCandidate struct {
	row    *Row
	sevIdx int
}

// runNext prints the next pending row(s) the operator should pick up.
// Filters compose: feature narrows to one file, severity narrows to
// one P-tier, count caps the result list. The default order is
// P0 → P1 → P2, then by row ID within a severity.
func runNext(dir, testRoot, feature, severity string, count int) error {
	cat, err := loadCatalog(dir)
	if err != nil {
		return err
	}
	if count <= 0 {
		count = 1
	}
	if severity != "" && severityIndex(severity) < 0 {
		return fmt.Errorf("next: severity %q must be one of P0|P1|P2", severity)
	}

	cands := pendingCandidates(cat, feature, severity)
	if len(cands) == 0 {
		fmt.Println("scenariotool: no pending rows match the filters")
		return nil
	}
	sortPendingCandidates(cands)
	if count > len(cands) {
		count = len(cands)
	}

	for i := range count {
		printPendingRow(cat, cands[i].row, testRoot)
		if i+1 < count {
			fmt.Println()
		}
	}
	return nil
}

// pendingCandidates selects the rows still awaiting a test, honouring
// the feature and severity filters. A row whose severity is outside
// P0|P1|P2 has no rank to sort by and is left out.
func pendingCandidates(cat *Catalog, feature, severity string) []pendingCandidate {
	var cands []pendingCandidate
	for _, r := range cat.AllRows() {
		if feature != "" && r.File.Feature != feature {
			continue
		}
		if severity != "" && r.Severity != severity {
			continue
		}
		if r.EffectiveStatus() != "pending" {
			continue
		}
		idx := severityIndex(r.Severity)
		if idx < 0 {
			continue
		}
		cands = append(cands, pendingCandidate{row: r, sevIdx: idx})
	}
	return cands
}

// sortPendingCandidates orders by severity first, then by row ID, so
// repeated runs hand out the same work in the same order.
func sortPendingCandidates(cands []pendingCandidate) {
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].sevIdx != cands[j].sevIdx {
			return cands[i].sevIdx < cands[j].sevIdx
		}
		return cands[i].row.ID < cands[j].row.ID
	})
}

// printPendingRow renders one row with the location its test would
// occupy, so the reader can go straight to the file.
func printPendingRow(cat *Catalog, r *Row, testRoot string) {
	loc, err := locateTest(r, testRoot)
	locStr := loc.File
	switch {
	case err != nil:
		locStr += " (locate error: " + err.Error() + ")"
	case loc.Found:
		locStr = fmt.Sprintf("%s:%d", loc.File, loc.Line)
	default:
		locStr += " (no stub yet)"
	}
	fmt.Printf("%s  %s  pending  %s\n", r.ID, r.Severity, locStr)
	fmt.Printf("  spec:      %s\n", singleLine(r.Spec))
	fmt.Printf("  behaviour: %s\n", indented(r.Behaviour))
	if len(r.CrossRefs) > 0 {
		fmt.Printf("  cross_refs: %s\n", strings.Join(crossRefAnnotations(cat, r.CrossRefs), ", "))
	}
}

// crossRefAnnotations decorates each cross_ref string with the target
// row's effective status (or "[unknown]" when the ID is missing).
func crossRefAnnotations(cat *Catalog, refs []string) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		parts := strings.SplitN(ref, "#", 2)
		if len(parts) != 2 {
			out = append(out, ref)
			continue
		}
		target := cat.Lookup(parts[1])
		if target == nil {
			out = append(out, ref+" [unknown]")
			continue
		}
		out = append(out, ref+" ["+target.EffectiveStatus()+"]")
	}
	return out
}
