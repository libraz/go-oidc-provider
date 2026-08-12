package main

import (
	"fmt"
	"sort"
)

// severityCell is the active / pending / out-of-scope split for one
// severity tier.
type severityCell struct {
	active, pending, oos int
}

// featureCell is the per-file breakdown: total rows plus an
// (active, pending) pair per severity, indexed by severityIndex.
type featureCell struct {
	feature string
	rows    int
	ap      [3][2]int
}

// catalogTally is the aggregate runStats renders. It is built in one
// pass over the catalog so the totals and the per-feature breakdown
// can never disagree.
type catalogTally struct {
	bySeverity map[string]*severityCell
	perFeature map[string]*featureCell
}

// runStats prints a severity × status matrix plus a per-feature
// breakdown sorted by descending P0 pending count. When feature is
// non-empty only that file's rows are tallied, and the per-feature
// section is suppressed.
func runStats(dir, feature string) error {
	cat, err := loadCatalog(dir)
	if err != nil {
		return err
	}
	tally, matched := tallyCatalog(cat, feature)
	if feature != "" && !matched {
		return &exitError{code: 1, message: fmt.Sprintf("scenariotool: no catalog file for feature %q", feature)}
	}

	tally.printTotals(feature)
	if feature != "" {
		return nil
	}
	tally.printTopP0Pending()
	tally.printPerFeatureBreakdown()
	return nil
}

// tallyCatalog accumulates every row of the catalog, optionally
// narrowed to one feature. matched reports whether the requested
// feature file exists, which the caller turns into an exit code.
func tallyCatalog(cat *Catalog, feature string) (tally *catalogTally, matched bool) {
	tally = &catalogTally{
		bySeverity: map[string]*severityCell{"P0": {}, "P1": {}, "P2": {}},
		perFeature: map[string]*featureCell{},
	}
	for _, ff := range cat.Files {
		if feature != "" && ff.Feature != feature {
			continue
		}
		matched = true
		fc := tally.perFeature[ff.Feature]
		if fc == nil {
			fc = &featureCell{feature: ff.Feature}
			tally.perFeature[ff.Feature] = fc
		}
		for _, r := range ff.Rows {
			tally.addRow(fc, r)
		}
	}
	return tally, matched
}

// addRow folds one row into both the severity totals and its feature's
// breakdown. A row whose severity is outside P0|P1|P2 still counts
// towards the feature's row total but has no tier to land in; the
// catalog validator is what rejects it.
func (t *catalogTally) addRow(fc *featureCell, r *Row) {
	fc.rows++
	c, ok := t.bySeverity[r.Severity]
	if !ok {
		return
	}
	sevIdx := severityIndex(r.Severity)
	switch r.EffectiveStatus() {
	case "active":
		c.active++
		if sevIdx >= 0 {
			fc.ap[sevIdx][0]++
		}
	case "out-of-scope":
		c.oos++
	default: // pending or unknown defaults to pending bucket
		c.pending++
		if sevIdx >= 0 {
			fc.ap[sevIdx][1]++
		}
	}
}

// printTotals renders the severity × status matrix. The percentage is
// taken over in-scope rows only, so declaring a row out-of-scope moves
// it out of the denominator rather than counting as progress.
func (t *catalogTally) printTotals(feature string) {
	totalActive, totalPending, totalOOS := 0, 0, 0
	for _, c := range t.bySeverity {
		totalActive += c.active
		totalPending += c.pending
		totalOOS += c.oos
	}
	inScope := totalActive + totalPending
	pct := 0.0
	if inScope > 0 {
		pct = 100 * float64(totalActive) / float64(inScope)
	}

	header := "catalog totals"
	if feature != "" {
		header = "catalog totals — " + feature
	}
	fmt.Printf("%s:\n", header)
	fmt.Printf("  %-6s  %7s  %7s  %4s  %5s\n", "", "active", "pending", "oos", "total")
	for _, sev := range []string{"P0", "P1", "P2"} {
		c := t.bySeverity[sev]
		fmt.Printf("  %-6s  %7d  %7d  %4d  %5d\n", sev, c.active, c.pending, c.oos, c.active+c.pending+c.oos)
	}
	fmt.Printf("  %-6s  %7d  %7d  %4d  %5d   (%.1f%% active of in-scope)\n",
		"total", totalActive, totalPending, totalOOS, totalActive+totalPending+totalOOS, pct)
}

// printTopP0Pending lists the features carrying the most unwritten P0
// rows, capped at ten. It is the pick-up-next view: P0 pending is the
// only backlog that blocks the suite from claiming a behaviour is
// covered.
func (t *catalogTally) printTopP0Pending() {
	type featurePending struct {
		name string
		p0p  int
	}
	top := make([]featurePending, 0, len(t.perFeature))
	for _, fc := range t.perFeature {
		top = append(top, featurePending{name: fc.feature, p0p: fc.ap[0][1]})
	}
	sort.Slice(top, func(i, j int) bool {
		if top[i].p0p != top[j].p0p {
			return top[i].p0p > top[j].p0p
		}
		return top[i].name < top[j].name
	})

	fmt.Println()
	fmt.Println("top P0 pending features:")
	shown := 0
	for _, f := range top {
		if f.p0p == 0 {
			break
		}
		fmt.Printf("  %-32s  %4d\n", f.name, f.p0p)
		shown++
		if shown >= 10 {
			break
		}
	}
	if shown == 0 {
		fmt.Println("  (none — every feature is fully active or has no P0 pending)")
	}
}

// printPerFeatureBreakdown renders every feature in name order with its
// active/pending pair per severity.
func (t *catalogTally) printPerFeatureBreakdown() {
	fmt.Println()
	fmt.Println("per-feature breakdown (active/pending per severity):")
	fmt.Printf("  %-32s  %-7s  %-7s  %-7s  %s\n", "feature", "P0", "P1", "P2", "total")
	names := make([]string, 0, len(t.perFeature))
	for n := range t.perFeature {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fc := t.perFeature[n]
		fmt.Printf("  %-32s  %-7s  %-7s  %-7s  %5d\n",
			n,
			cellStr(fc.ap[0]),
			cellStr(fc.ap[1]),
			cellStr(fc.ap[2]),
			fc.rows,
		)
	}
}

// severityIndex maps a severity tier onto its slot in featureCell.ap,
// or -1 when the tier is not one the catalog recognises.
func severityIndex(sev string) int {
	switch sev {
	case "P0":
		return 0
	case "P1":
		return 1
	case "P2":
		return 2
	}
	return -1
}

// cellStr renders one (active, pending) pair, collapsing an empty pair
// to a dash so the table stays scannable.
func cellStr(ap [2]int) string {
	if ap[0] == 0 && ap[1] == 0 {
		return "-"
	}
	return fmt.Sprintf("%d/%d", ap[0], ap[1])
}
