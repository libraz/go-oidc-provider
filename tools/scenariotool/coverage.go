package main

import (
	"bufio"
	"context"
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
func runCoverage(ctx context.Context, dir, testsPattern, cwd, testRoot string, strict, checkBindings, yamlOnly bool) error {
	cat, err := loadCatalog(dir)
	if err != nil {
		return err
	}

	rows := map[string]rowBinding{}
	for _, r := range cat.AllRows() {
		rows[r.ID] = rowBinding{status: r.EffectiveStatus(), coveredBy: r.CoveredBy}
	}

	if yamlOnly {
		reportYAMLOnlyCoverage(rows)
		return nil
	}

	testIDs, err := discoverTestIDs(ctx, testsPattern, cwd)
	if err != nil {
		return err
	}
	stubs, classified, err := discoverSkipStubs(testRoot)
	if err != nil {
		return err
	}
	if err := checkStubScanReachedTests(testRoot, len(testIDs), classified); err != nil {
		return err
	}
	brokenDelegations, err := verifyDelegations(ctx, rows, cwd)
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

// checkStubScanReachedTests refuses to report coverage when `go test
// -list` found scenario tests but the source scan classified none of
// them.
//
// The two disagreeing means the scan did not read the tests it is meant
// to judge — a wrong or empty -test-root, a renamed tree, a layout the
// walk no longer matches. Every such case yields an empty stub set,
// which is indistinguishable from the healthy "nothing is a stub"
// answer: skip-only drops to zero, every bound row is credited, and the
// gate reports full coverage having verified nothing. That is the same
// false green the classifier itself was fixed to stop producing, one
// layer up, so it is refused here rather than reported.
//
// The supported way to run without the scan is -yaml-only, which skips
// the `go test -list` side too and so cannot claim a binding it did not
// check.
func checkStubScanReachedTests(testRoot string, testCount, classified int) error {
	if testCount == 0 || classified > 0 {
		return nil
	}
	where := testRoot
	if where == "" {
		where = "(empty -test-root)"
	}
	return fmt.Errorf(
		"`go test -list` found %d scenario test(s) but the source scan under %s classified none; "+
			"the skip-stub scan is not reading the suite, so every binding would be credited unverified "+
			"(use -yaml-only to report the catalog side alone)",
		testCount, where,
	)
}

// reportYAMLOnlyCoverage prints the status split that can be derived
// from the catalog alone. It is the fallback for a main module that
// currently fails to build, where `go test -list` cannot answer and a
// real binding diff is unobtainable.
func reportYAMLOnlyCoverage(rows map[string]rowBinding) {
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
		_, stub := stubs[id]
		if row.status == "out-of-scope" {
			// A skip stub under an out-of-scope row is the documented
			// way to leave a marker where the test would go; a test
			// that runs contradicts the row.
			if hasTest && !stub {
				res.assertedOutOfScope = append(res.assertedOutOfScope, id)
			}
			continue
		}
		res.inScope++
		res.classifyInScopeRow(id, row, hasTest, stub, brokenDelegations)
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

// classifyInScopeRow buckets one row that is not out-of-scope. The
// order of the cases is the precedence the gate depends on: a row that
// delegates is answered by its delegation whatever the suite holds,
// because the assertion deliberately lives elsewhere and the local
// skip stub is only a marker.
func (r *coverageResult) classifyInScopeRow(id string, row rowBinding, hasTest, stub bool, brokenDelegations map[string]string) {
	switch {
	case row.coveredBy != "":
		// A delegation that resolved is coverage; one that did not
		// is a claim about a test that no longer exists, which is
		// the failure this field was added to make visible.
		if reason, broken := brokenDelegations[id]; broken {
			r.brokenDelegations = append(r.brokenDelegations, fmt.Sprintf("%s: %s", id, reason))
			return
		}
		r.bound++
		r.delegated++
	case !hasTest:
		r.missingTests = append(r.missingTests, id)
	case stub:
		r.skippedBindings = append(r.skippedBindings, id)
	default:
		r.bound++
	}
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
func discoverTestIDs(ctx context.Context, pattern, cwd string) (map[string]struct{}, error) {
	cmd := exec.CommandContext(ctx, "go", "test", "-list", "Test.*", pattern) //nolint:gosec // operator-supplied pattern.
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
func verifyDelegations(ctx context.Context, rows map[string]rowBinding, cwd string) (map[string]string, error) {
	byPackage, broken := groupDelegations(rows)
	for pkg, refs := range byPackage {
		resolvePackageDelegations(ctx, pkg, refs, cwd, broken)
	}
	return broken, nil
}

// delegationRef is one row's claim that its assertion lives in another
// package.
type delegationRef struct{ rowID, testName string }

// groupDelegations buckets every covered_by by the package it names, so
// one `go test -list` answers for every row delegating into it. Rows
// whose covered_by has no package/function separator cannot be grouped
// and are reported as broken immediately — the shape itself is the
// validator's job, so this only has to avoid guessing.
func groupDelegations(rows map[string]rowBinding) (map[string][]delegationRef, map[string]string) {
	byPackage := map[string][]delegationRef{}
	broken := map[string]string{}
	for id, row := range rows {
		if row.coveredBy == "" {
			continue
		}
		pkg, testName, ok := strings.Cut(row.coveredBy, ".")
		if !ok || pkg == "" || testName == "" {
			broken[id] = fmt.Sprintf("covered_by %q is not <package>.<TestFunc>", row.coveredBy)
			continue
		}
		byPackage[pkg] = append(byPackage[pkg], delegationRef{rowID: id, testName: testName})
	}
	return byPackage, broken
}

// resolvePackageDelegations lists one package's tests and records a
// reason for every reference it does not answer for.
func resolvePackageDelegations(ctx context.Context, pkg string, refs []delegationRef, cwd string, broken map[string]string) {
	found, err := listTests(ctx, delegationListPattern(refs), "./"+pkg, cwd)
	if err != nil {
		// A package that will not build cannot answer the question.
		// Say which rows are unverifiable rather than reporting them
		// as absent.
		for _, r := range refs {
			broken[r.rowID] = fmt.Sprintf("covered_by %s.%s: package would not build (%v)", pkg, r.testName, err)
		}
		return
	}
	for _, r := range refs {
		if _, ok := found[r.testName]; !ok {
			broken[r.rowID] = fmt.Sprintf("covered_by names %s.%s, which %s does not declare", pkg, r.testName, pkg)
		}
	}
}

// delegationListPattern builds the anchored alternation `go test -list`
// is given. Names are quoted so a test name is never read as a regex,
// and sorted so the command line is stable across runs.
func delegationListPattern(refs []delegationRef) string {
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, regexp.QuoteMeta(r.testName))
	}
	sort.Strings(names)
	return "^(" + strings.Join(names, "|") + ")$"
}

// listTests runs `go test -list <pattern> <pkg>` and returns the set of
// function names it reported.
func listTests(ctx context.Context, pattern, pkg, cwd string) (map[string]struct{}, error) {
	cmd := exec.CommandContext(ctx, "go", "test", "-list", pattern, pkg) //nolint:gosec // pattern is derived from the catalog.
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
// function is a skip stub, alongside the number of scenario test
// functions the scan classified at all.
//
// A row keeps its binding as soon as one of its tests runs, so an ID
// only lands here when nothing under it asserts.
//
// The second return exists because an empty stub set is ambiguous on
// its own: it means either "every bound test asserts" (the healthy
// state) or "the scan read nothing" (a broken scan). Those two produce
// an identical, passing dashboard, so the caller needs the classified
// count to tell them apart. An empty testRoot yields zero of both and
// is likewise the caller's to reject.
func discoverSkipStubs(testRoot string) (map[string]struct{}, int, error) {
	stubs := map[string]struct{}{}
	if testRoot == "" {
		return stubs, 0, nil
	}
	asserting := map[string]struct{}{}
	err := filepath.WalkDir(testRoot, func(path string, d os.DirEntry, walkErr error) error {
		switch {
		case walkErr != nil:
			return walkErr
		case d.IsDir() || !strings.HasSuffix(path, "_test.go"):
			return nil
		}
		return collectSkipStubs(path, stubs, asserting)
	})
	if err != nil {
		return nil, 0, fmt.Errorf("walk %s: %w", testRoot, err)
	}
	// Distinct IDs seen, counted before the subtraction below: that
	// subtraction only moves IDs between the two sets and must not change
	// how much the scan is credited with having read. An ID carrying both
	// a stub and an asserting function counts once.
	seen := make(map[string]struct{}, len(stubs)+len(asserting))
	for id := range stubs {
		seen[id] = struct{}{}
	}
	for id := range asserting {
		seen[id] = struct{}{}
	}
	for id := range asserting {
		delete(stubs, id)
	}
	return stubs, len(seen), nil
}

// collectSkipStubs records every scenario test declared in one file as
// either a skip stub or an asserting test. Both sets are needed because
// a row may carry several test functions and keeps its binding as soon
// as one of them asserts.
func collectSkipStubs(path string, stubs, asserting map[string]struct{}) error {
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
		if neverAsserts(fd.Body) {
			stubs[id] = struct{}{}
		} else {
			asserting[id] = struct{}{}
		}
	}
	return nil
}

// neverAsserts reports whether a test body cannot fail: it either opens
// with an unconditional t.Skip / t.Skipf / t.SkipNow, or it never gets
// as far as a statement that could assert anything.
//
// Bookkeeping calls that every scenario test opens with are stepped
// over. A skip nested in an if — the "no Docker here, skip" shape — is
// not a stub: that test asserts whenever its precondition holds.
//
// Running off the end of the list is the second stub shape and returns
// true. A body that is empty, or that holds nothing but the bookkeeping
// calls above, has no statement that can fail — so counting it as
// coverage would let an empty function stand in for an assertion, which
// is the one thing a coverage gate must not accept. Only a statement
// the walk cannot classify as bookkeeping is evidence of real work.
func neverAsserts(body *ast.BlockStmt) bool {
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
	return true
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
