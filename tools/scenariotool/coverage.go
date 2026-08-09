package main

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// testNameRE matches the Test_<PREFIX>(_<SUB>)*_<NNN>_<Slug> shape used by
// the scenario suite. The optional "Scenario_" prefix lets us pick up the
// existing TestScenario_DIS_001_* convention without forcing a rename if
// someone drops the marker; either form binds the same way.
//
// The number may carry a trailing variant letter (DEV_007B). A catalog ID
// cannot express one — the schema ends every ID in digits — so the letter
// is parsed and dropped, binding the variant to the same row as the base
// number. The slug is allowed to contain underscores; a multi-word slug
// otherwise makes the test invisible to this gate, which is the worst
// possible outcome for a name-based binding.
var testNameRE = regexp.MustCompile(`^Test(?:Scenario)?_?([A-Z][A-Z0-9]*(?:_[A-Z][A-Z0-9]*)*)_([0-9]+)[A-Z]?(?:_[A-Za-z0-9_]+)?$`)

// rowBinding is the part of a catalog row the coverage gate reads.
type rowBinding struct {
	status    string
	coveredBy string // "<package>.<TestFunc>", empty when not delegated
}

// coverageResult is the binding picture for one catalog / test-tree pair.
type coverageResult struct {
	// missingTests are in-scope rows with no Test_* function at all.
	missingTests []string
	// unboundTests are test functions whose ID matches no catalog row.
	unboundTests []string
	// assertedOutOfScope are out-of-scope rows whose test actually runs.
	// The row says the behaviour is unreachable and the test says
	// otherwise; one of the two is wrong.
	assertedOutOfScope []string
	// skippedBindings are in-scope rows whose every test function opens
	// with an unconditional t.Skip. The row counts as bound by name and
	// asserts nothing.
	skippedBindings []string
	// brokenDelegations are rows whose covered_by names a test that no
	// longer exists, one message per row.
	brokenDelegations []string
	// bound is the number of in-scope rows with at least one test that
	// actually runs, delegated coverage included once resolved.
	bound int
	// delegated is how many of bound are covered outside the suite.
	delegated int
	// inScope is the number of rows that are not out-of-scope.
	inScope int
}

// runCoverage compares catalog row IDs with the scenario test
// functions discovered via `go test -list`. Out-of-scope rows are
// excluded from both directions. When yamlOnly is true, the
// `go test -list` step is skipped and only the YAML side of the
// dashboard is rendered — useful when the main module currently fails
// to build and a full coverage diff is unobtainable.
//
// A name alone is not coverage: `go test -list` reports a function that
// begins with t.Skip exactly as it reports one that asserts, so the
// binding is also resolved against the test sources under testRoot. A
// row bound only to a skip stub is reported separately rather than
// counted.
func runCoverage(dir, testsPattern, cwd, testRoot string, strict, checkBindings, yamlOnly bool) error {
	cat, err := loadCatalog(dir)
	if err != nil {
		return err
	}

	rows := map[string]rowBinding{}
	for _, r := range cat.AllRows() {
		rows[r.ID] = rowBinding{status: r.EffectiveStatus(), coveredBy: r.CoveredBy}
	}

	if yamlOnly {
		var active, pending, oos int
		for _, row := range rows {
			switch row.status {
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
	stubs, err := discoverSkipStubs(testRoot)
	if err != nil {
		return err
	}
	brokenDelegations, err := verifyDelegations(rows, cwd)
	if err != nil {
		return err
	}

	res := classifyCoverage(rows, testIDs, stubs, brokenDelegations)
	res.report()

	if strict && res.failing(true) {
		return &exitError{code: 1, message: "scenariotool: coverage gate failed (--strict)"}
	}
	if checkBindings && res.failing(false) {
		return &exitError{code: 1, message: "scenariotool: binding gate failed (--check-bindings)"}
	}
	return nil
}

// failing reports whether the result should fail a gate. Skip-only
// bindings are the one class the binding gate tolerates: they are a
// progress signal, and a gate nobody can turn green is a gate people
// learn to bypass. Everything else is drift between two things that
// claim to describe each other.
func (r *coverageResult) failing(includeSkipOnly bool) bool {
	if includeSkipOnly && len(r.skippedBindings) > 0 {
		return true
	}
	return len(r.missingTests) > 0 || len(r.unboundTests) > 0 ||
		len(r.assertedOutOfScope) > 0 || len(r.brokenDelegations) > 0
}

// classifyCoverage sorts every row and every discovered test into the
// buckets the report and the gates read. brokenDelegations maps a row ID
// to the reason its covered_by could not be resolved.
func classifyCoverage(rows map[string]rowBinding, testIDs, stubs map[string]struct{}, brokenDelegations map[string]string) *coverageResult {
	res := &coverageResult{}
	for id, row := range rows {
		_, hasTest := testIDs[id]
		if row.status == "out-of-scope" {
			// A skip stub under an out-of-scope row is the documented
			// way to leave a marker where the test would go; a test
			// that runs contradicts the row.
			if _, stub := stubs[id]; hasTest && !stub {
				res.assertedOutOfScope = append(res.assertedOutOfScope, id)
			}
			continue
		}
		res.inScope++
		_, stub := stubs[id]
		switch {
		case row.coveredBy != "":
			// A delegation that resolved is coverage; one that did not
			// is a claim about a test that no longer exists, which is
			// the failure this field was added to make visible.
			if reason, broken := brokenDelegations[id]; broken {
				res.brokenDelegations = append(res.brokenDelegations,
					fmt.Sprintf("%s: %s", id, reason))
			} else {
				res.bound++
				res.delegated++
			}
		case !hasTest:
			res.missingTests = append(res.missingTests, id)
		case stub:
			res.skippedBindings = append(res.skippedBindings, id)
		default:
			res.bound++
		}
	}
	for id := range testIDs {
		if _, ok := rows[id]; !ok {
			res.unboundTests = append(res.unboundTests, id)
		}
	}
	sort.Strings(res.missingTests)
	sort.Strings(res.unboundTests)
	sort.Strings(res.assertedOutOfScope)
	sort.Strings(res.skippedBindings)
	sort.Strings(res.brokenDelegations)
	return res
}

// report prints the dashboard. Every failing class names the rows so the
// reader never has to re-derive them from the counts.
func (r *coverageResult) report() {
	pct := 0
	if r.inScope > 0 {
		pct = 100 * r.bound / r.inScope
	}
	fmt.Printf("scenariotool: catalog rows (in-scope) %d, bound %d (delegated %d), skip-only %d, missing tests %d, unbound tests %d, coverage %d%%\n",
		r.inScope, r.bound, r.delegated, len(r.skippedBindings), len(r.missingTests), len(r.unboundTests), pct)

	printIDs("missing tests (catalog row without TestScenario_*)", r.missingTests)
	printIDs("unbound tests (TestScenario_* with no catalog row)", r.unboundTests)
	printIDs("out-of-scope rows whose test runs (row says unreachable, test disagrees)", r.assertedOutOfScope)
	printIDs("skip-only bindings (row bound to a TestScenario_* that opens with t.Skip)", r.skippedBindings)
	printIDs("broken delegations (covered_by names a test that does not exist)", r.brokenDelegations)
}

// printIDs prints a titled block, or nothing when the block is empty.
func printIDs(title string, ids []string) {
	if len(ids) == 0 {
		return
	}
	fmt.Printf("%s:\n", title)
	for _, id := range ids {
		fmt.Printf("  %s\n", id)
	}
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
		id, ok := scenarioIDFromTestName(strings.TrimSpace(scanner.Text()))
		if !ok {
			continue
		}
		ids[id] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan go test output: %w", err)
	}
	return ids, nil
}

// verifyDelegations resolves every covered_by reference against the test
// functions the named package actually declares, and returns a reason
// for each row whose reference does not resolve.
//
// This is the whole value of the field over the prose it replaces: a
// sentence saying "covered by X" stays readable forever after X is
// renamed, and nothing notices. `go test -list` notices.
func verifyDelegations(rows map[string]rowBinding, cwd string) (map[string]string, error) {
	// Group by package so one `go test -list` answers for every row
	// that delegates into it.
	type ref struct{ rowID, testName string }
	byPackage := map[string][]ref{}
	broken := map[string]string{}
	for id, row := range rows {
		if row.coveredBy == "" {
			continue
		}
		pkg, testName, ok := strings.Cut(row.coveredBy, ".")
		if !ok || pkg == "" || testName == "" {
			// Shape is the validator's job; skip rather than guess.
			broken[id] = fmt.Sprintf("covered_by %q is not <package>.<TestFunc>", row.coveredBy)
			continue
		}
		byPackage[pkg] = append(byPackage[pkg], ref{rowID: id, testName: testName})
	}

	for pkg, refs := range byPackage {
		names := make([]string, 0, len(refs))
		for _, r := range refs {
			names = append(names, regexp.QuoteMeta(r.testName))
		}
		sort.Strings(names)
		pattern := "^(" + strings.Join(names, "|") + ")$"
		found, err := listTests(pattern, "./"+pkg, cwd)
		if err != nil {
			// A package that will not build cannot answer the
			// question. Say which rows are unverifiable rather than
			// reporting them as absent.
			for _, r := range refs {
				broken[r.rowID] = fmt.Sprintf("covered_by %s.%s: package would not build (%v)", pkg, r.testName, err)
			}
			continue
		}
		for _, r := range refs {
			if _, ok := found[r.testName]; !ok {
				broken[r.rowID] = fmt.Sprintf("covered_by names %s.%s, which %s does not declare", pkg, r.testName, pkg)
			}
		}
	}
	return broken, nil
}

// listTests runs `go test -list <pattern> <pkg>` and returns the set of
// function names it reported.
func listTests(pattern, pkg, cwd string) (map[string]struct{}, error) {
	cmd := exec.Command("go", "test", "-list", pattern, pkg) //nolint:gosec // pattern is derived from the catalog.
	if cwd != "" {
		cmd.Dir = cwd
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("go test -list %s: %w", pkg, err)
	}
	names := map[string]struct{}{}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Test") || strings.HasPrefix(line, "Fuzz") {
			names[line] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan go test output: %w", err)
	}
	return names, nil
}

// scenarioIDFromTestName maps a Go test function name onto the catalog
// ID it binds, or reports false when the name is not a scenario test.
func scenarioIDFromTestName(name string) (string, bool) {
	m := testNameRE.FindStringSubmatch(name)
	if m == nil {
		return "", false
	}
	return strings.ReplaceAll(m[1], "_", "-") + "-" + m[2], true
}

// discoverSkipStubs returns the set of scenario IDs whose every test
// function is a skip stub. A row keeps its binding as soon as one of
// its tests runs, so an ID only lands here when nothing under it
// asserts. An empty testRoot disables the scan and yields no stubs.
func discoverSkipStubs(testRoot string) (map[string]struct{}, error) {
	stubs := map[string]struct{}{}
	if testRoot == "" {
		return stubs, nil
	}
	asserting := map[string]struct{}{}
	err := filepath.WalkDir(testRoot, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		for _, decl := range file.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || fd.Body == nil {
				continue
			}
			id, ok := scenarioIDFromTestName(fd.Name.Name)
			if !ok {
				continue
			}
			if opensWithSkip(fd.Body) {
				stubs[id] = struct{}{}
			} else {
				asserting[id] = struct{}{}
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk %s: %w", testRoot, err)
	}
	for id := range asserting {
		delete(stubs, id)
	}
	return stubs, nil
}

// opensWithSkip reports whether the first statement that could do any
// work is an unconditional t.Skip / t.Skipf / t.SkipNow.
//
// Bookkeeping calls that every scenario test opens with are stepped
// over. A skip nested in an if — the "no Docker here, skip" shape — is
// not a stub: that test asserts whenever its precondition holds.
func opensWithSkip(body *ast.BlockStmt) bool {
	for _, stmt := range body.List {
		expr, ok := stmt.(*ast.ExprStmt)
		if !ok {
			return false
		}
		name, ok := calledTestingMethod(expr.X)
		if !ok {
			return false
		}
		switch name {
		case "Parallel", "Helper", "Cleanup", "Log", "Logf":
			continue
		case "Skip", "Skipf", "SkipNow":
			return true
		default:
			return false
		}
	}
	return false
}

// calledTestingMethod returns the method name of a `<ident>.<Method>()`
// call expression.
func calledTestingMethod(expr ast.Expr) (string, bool) {
	call, ok := expr.(*ast.CallExpr)
	if !ok {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	if _, ok := sel.X.(*ast.Ident); !ok {
		return "", false
	}
	return sel.Sel.Name, true
}
