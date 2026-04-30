package main

import (
	"fmt"
	"sort"
	"strings"
)

// runStats prints a severity × status matrix plus a per-feature
// breakdown sorted by descending P0 pending count. When feature is
// non-empty only that file's rows are tallied, and the per-feature
// section is suppressed.
func runStats(dir, feature string) error {
	cat, err := loadCatalog(dir)
	if err != nil {
		return err
	}

	type cell struct {
		active, pending, oos int
	}
	bySeverity := map[string]*cell{
		"P0": {}, "P1": {}, "P2": {},
	}
	type featureCell struct {
		feature string
		rows    int
		// per-severity (active, pending) pairs.
		ap [3][2]int
	}
	perFeature := map[string]*featureCell{}

	matched := false
	for _, ff := range cat.Files {
		if feature != "" && ff.Feature != feature {
			continue
		}
		matched = true
		fc := perFeature[ff.Feature]
		if fc == nil {
			fc = &featureCell{feature: ff.Feature}
			perFeature[ff.Feature] = fc
		}
		for _, r := range ff.Rows {
			fc.rows++
			c, ok := bySeverity[r.Severity]
			if !ok {
				continue
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
	}
	if feature != "" && !matched {
		return &exitError{code: 1, message: fmt.Sprintf("scenariotool: no catalog file for feature %q", feature)}
	}

	totalActive, totalPending, totalOOS := 0, 0, 0
	for _, c := range bySeverity {
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
		header = fmt.Sprintf("catalog totals — %s", feature)
	}
	fmt.Printf("%s:\n", header)
	fmt.Printf("  %-6s  %7s  %7s  %4s  %5s\n", "", "active", "pending", "oos", "total")
	for _, sev := range []string{"P0", "P1", "P2"} {
		c := bySeverity[sev]
		fmt.Printf("  %-6s  %7d  %7d  %4d  %5d\n", sev, c.active, c.pending, c.oos, c.active+c.pending+c.oos)
	}
	fmt.Printf("  %-6s  %7d  %7d  %4d  %5d   (%.1f%% active of in-scope)\n",
		"total", totalActive, totalPending, totalOOS, totalActive+totalPending+totalOOS, pct)

	if feature != "" {
		return nil
	}

	// Top P0 pending features.
	type fp struct {
		name string
		p0p  int
	}
	var top []fp
	for _, fc := range perFeature {
		top = append(top, fp{name: fc.feature, p0p: fc.ap[0][1]})
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

	// Per-feature breakdown.
	fmt.Println()
	fmt.Println("per-feature breakdown (active/pending per severity):")
	fmt.Printf("  %-32s  %-7s  %-7s  %-7s  %s\n", "feature", "P0", "P1", "P2", "total")
	names := make([]string, 0, len(perFeature))
	for n := range perFeature {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fc := perFeature[n]
		fmt.Printf("  %-32s  %-7s  %-7s  %-7s  %5d\n",
			n,
			cellStr(fc.ap[0]),
			cellStr(fc.ap[1]),
			cellStr(fc.ap[2]),
			fc.rows,
		)
	}
	return nil
}

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

func cellStr(ap [2]int) string {
	if ap[0] == 0 && ap[1] == 0 {
		return "-"
	}
	return fmt.Sprintf("%d/%d", ap[0], ap[1])
}

// snippet returns the first non-empty line of s, truncated to the
// supplied width. Used by stats / next to keep output scannable.
func snippet(s string, width int) string {
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t == "" {
			continue
		}
		if len(t) > width {
			return t[:width-1] + "…"
		}
		return t
	}
	return ""
}
