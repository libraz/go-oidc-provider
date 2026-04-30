package main

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

// testNameRE matches the Test_<PREFIX>(_<SUB>)*_<NNN>_<Slug> shape used by
// the scenario suite. The optional "Scenario_" prefix lets us pick up the
// existing TestScenario_DIS_001_* convention without forcing a rename if
// someone drops the marker; either form binds the same way.
var testNameRE = regexp.MustCompile(`^Test(?:Scenario_)?([A-Z][A-Z0-9]*(?:_[A-Z][A-Z0-9]*)*)_([0-9]+)(?:_[A-Za-z0-9]+)?$`)

// runCoverage compares catalog row IDs with the scenario test
// functions discovered via `go test -list`. Out-of-scope rows are
// excluded from both directions. When yamlOnly is true, the
// `go test -list` step is skipped and only the YAML side of the
// dashboard is rendered — useful when the main module currently fails
// to build and a full coverage diff is unobtainable.
func runCoverage(dir, testsPattern, cwd string, strict, yamlOnly bool) error {
	cat, err := loadCatalog(dir)
	if err != nil {
		return err
	}

	catalogIDs := map[string]string{} // id -> status
	for _, r := range cat.AllRows() {
		catalogIDs[r.ID] = r.EffectiveStatus()
	}

	if yamlOnly {
		var active, pending, oos int
		for _, status := range catalogIDs {
			switch status {
			case "active":
				active++
			case "out-of-scope":
				oos++
			default:
				pending++
			}
		}
		inScope := active + pending
		pct := 0
		if inScope > 0 {
			pct = 100 * active / inScope
		}
		fmt.Printf("scenariotool (yaml-only): rows %d (active %d, pending %d, out-of-scope %d) — coverage %d%%\n",
			active+pending+oos, active, pending, oos, pct)
		return nil
	}

	testIDs, err := discoverTestIDs(testsPattern, cwd)
	if err != nil {
		return err
	}

	var (
		missingTests []string // catalog rows without a Test_*
		unboundTests []string // Test_* without a catalog row
		bound        int
	)
	for id, status := range catalogIDs {
		if status == "out-of-scope" {
			continue
		}
		if _, ok := testIDs[id]; ok {
			bound++
		} else {
			missingTests = append(missingTests, id)
		}
	}
	for id := range testIDs {
		if status, ok := catalogIDs[id]; !ok || status == "out-of-scope" {
			unboundTests = append(unboundTests, id)
		}
	}
	sort.Strings(missingTests)
	sort.Strings(unboundTests)

	totalActive := 0
	for _, status := range catalogIDs {
		if status != "out-of-scope" {
			totalActive++
		}
	}
	pct := 0
	if totalActive > 0 {
		pct = 100 * bound / totalActive
	}

	fmt.Printf("scenariotool: catalog rows (in-scope) %d, bound %d, missing tests %d, unbound tests %d, coverage %d%%\n",
		totalActive, bound, len(missingTests), len(unboundTests), pct)

	if len(missingTests) > 0 {
		fmt.Println("missing tests (catalog row without TestScenario_*):")
		for _, id := range missingTests {
			fmt.Printf("  %s\n", id)
		}
	}
	if len(unboundTests) > 0 {
		fmt.Println("unbound tests (TestScenario_* with no catalog row):")
		for _, id := range unboundTests {
			fmt.Printf("  %s\n", id)
		}
	}

	if strict && (len(missingTests) > 0 || len(unboundTests) > 0) {
		return &exitError{code: 1, message: "scenariotool: coverage gate failed (--strict)"}
	}
	return nil
}

// discoverTestIDs runs `go test -list 'Test.*' <pattern>` and parses
// scenario IDs out of the matching function names. When cwd is
// non-empty the command runs from that directory (typically the main
// module's root, since scenariotool itself lives in a sibling module).
func discoverTestIDs(pattern, cwd string) (map[string]struct{}, error) {
	cmd := exec.Command("go", "test", "-list", "Test.*", pattern) //nolint:gosec // operator-supplied pattern.
	if cwd != "" {
		cmd.Dir = cwd
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("go test -list %s: %w\n%s", pattern, err, string(out))
	}
	ids := map[string]struct{}{}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		m := testNameRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		prefix := strings.ReplaceAll(m[1], "_", "-")
		ids[prefix+"-"+m[2]] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan go test output: %w", err)
	}
	return ids, nil
}
