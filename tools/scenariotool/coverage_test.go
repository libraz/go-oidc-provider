package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScenarioIDFromTestName(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		want   string
		wantOK bool
	}{
		{name: "TestScenario_DIS_001_DiscoveryDocument", want: "DIS-001", wantOK: true},
		{name: "Test_DIS_001_DiscoveryDocument", want: "DIS-001", wantOK: true},
		{name: "TestScenario_DIS_001", want: "DIS-001", wantOK: true},
		// A variant letter binds to the base row: the catalog schema
		// ends every ID in digits, so DEV-007B is not expressible and
		// the variant belongs to DEV-007.
		{name: "TestScenario_DEV_007B_DeviceAuthRejectsDuplicateScope", want: "DEV-007", wantOK: true},
		{name: "TestScenario_PW_10B_SingleHostRedirectURIsCompare", want: "PW-10", wantOK: true},
		// Multi-word slugs stay visible; an invisible test is worse
		// than an unbound one because nothing reports it.
		{name: "TestScenario_TE_012_Delegation_Parameters_Survive", want: "TE-012", wantOK: true},
		{name: "TestScenario_GRANT_MGMT_004_RevokeCascades", want: "GRANT-MGMT-004", wantOK: true},
		// Not scenario tests.
		{name: "TestCustomGrant_IDTokenSigning_FromExtraClaims", wantOK: false},
		{name: "TestEndpoints_OversizedJWSIsRefused", wantOK: false},
		{name: "TestHelper", wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := scenarioIDFromTestName(tc.name)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (id=%q)", ok, tc.wantOK, got)
			}
			if ok && got != tc.want {
				t.Errorf("id = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDiscoverSkipStubs(t *testing.T) {
	t.Parallel()
	src := `package scenarios

import "testing"

// A bare skip asserts nothing, however well the comment reads.
func TestScenario_AAA_001_Stub(t *testing.T) {
	t.Parallel()
	t.Skip("covered elsewhere")
}

func TestScenario_AAA_002_Asserts(t *testing.T) {
	t.Parallel()
	if 1 != 1 {
		t.Fatal("no")
	}
}

// A guarded skip still asserts whenever its precondition holds.
func TestScenario_AAA_003_Conditional(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	t.Fatal("boom")
}

// One asserting test is enough to bind the row, whichever order the
// variants appear in.
func TestScenario_AAA_004_Stub(t *testing.T) {
	t.Skip("pending")
}

func TestScenario_AAA_004B_Asserts(t *testing.T) {
	t.Fatal("boom")
}

// An empty body cannot fail, so it is not coverage. Counting it would
// let a row be bound by a function that asserts nothing at all — the
// same false green a bare skip produces, minus the skip.
func TestScenario_AAA_005_Empty(t *testing.T) {
}

// Neither is a body that only sets the test up.
func TestScenario_AAA_006_BookkeepingOnly(t *testing.T) {
	t.Parallel()
	t.Helper()
	t.Log("nothing asserted here")
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x_test.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	stubs, classified, err := discoverSkipStubs(dir)
	if err != nil {
		t.Fatalf("discoverSkipStubs: %v", err)
	}
	// The scan finding nothing at all would satisfy every "should not be
	// a stub" row below, so the populated direction is checked first.
	if len(stubs) == 0 {
		t.Fatal("no stubs discovered at all: the scan is broken, not the fixture")
	}
	if want := 6; classified != want {
		t.Errorf("classified = %d, want %d: the count the broken-scan guard reads must track "+
			"the IDs actually read, or the guard cannot tell a healthy suite from an unread one", classified, want)
	}
	for _, id := range []string{"AAA-001", "AAA-005", "AAA-006"} {
		if _, ok := stubs[id]; !ok {
			t.Errorf("%s should be a stub: nothing in its body can fail", id)
		}
	}
	for _, id := range []string{"AAA-002", "AAA-003", "AAA-004"} {
		if _, ok := stubs[id]; ok {
			t.Errorf("%s should not be a skip stub", id)
		}
	}
}

// TestCheckStubScanReachedTests pins the disagreement that means the
// skip-stub scan is not reading the suite it judges.
//
// An empty stub set is ambiguous: it is what a healthy suite produces
// and also what a scan that read nothing produces. The second reads out
// as skip-only 0 and full coverage, so without this check a wrong
// -test-root reports a perfect score having verified no binding at all.
func TestCheckStubScanReachedTests(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		testCount  int
		classified int
		wantErr    bool
	}{
		{"scan read the suite", 1200, 1200, false},
		{"scan read part of the suite", 1200, 3, false},
		{"no tests to read", 0, 0, false},
		{"tests exist but the scan read none", 1200, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkStubScanReachedTests("test/scenarios", tc.testCount, tc.classified)
			if tc.wantErr && err == nil {
				t.Fatal("no error: a scan that classified nothing would credit every binding unverified")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestRunCoverage_RefusesToPassWhenTheStubScanReadsNothing drives the
// whole gate rather than the guard alone, because the defect only
// exists once the pieces are joined: `go test -list` names a test, the
// source scan reads none, and the row is credited to a function that
// asserts nothing.
//
// The fixture's only scenario test is a skip stub, so a run whose scan
// works fails --strict on the skip-only binding. Each case below points
// -test-root at somewhere holding no test source — what a wrong -cwd, a
// renamed tree or a forgotten flag produces — and the run that must
// fail would otherwise report full coverage.
func TestRunCoverage_RefusesToPassWhenTheStubScanReadsNothing(t *testing.T) {
	t.Parallel()
	catalogDir, moduleDir, suiteDir := writeCoverageFixture(t)

	// The control run: the scan reaches the suite and the gate fails on
	// the skip-only binding it is meant to see. Without it, a broken-scan
	// case below could fail for a reason unrelated to the guard.
	err := runCoverage(t.Context(), catalogDir, "./scenarios/...", moduleDir, suiteDir, true, false, false)
	var exit *exitError
	if !errors.As(err, &exit) {
		t.Fatalf("scan reaching the suite: err = %v, want --strict to fail on the skip-only binding", err)
	}

	cases := []struct{ name, testRoot string }{
		{"empty -test-root", ""},
		{"-test-root holding no test source", t.TempDir()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := runCoverage(t.Context(), catalogDir, "./scenarios/...", moduleDir, tc.testRoot, true, false, false)
			if err == nil {
				t.Fatal("coverage --strict passed: the row is bound to a skip stub the scan never read, " +
					"so the gate reported coverage it did not verify")
			}
			if !strings.Contains(err.Error(), "classified none") {
				t.Errorf("err = %v, want the unread scan reported as a breakage rather than as a binding gap", err)
			}
		})
	}
}

// writeCoverageFixture builds the smallest tree runCoverage can run
// against: a one-row catalog, and a module whose only scenario test is
// a skip stub bound to that row. It returns the catalog directory, the
// module root `go test -list` runs in, and the suite directory the
// skip-stub scan is meant to read.
func writeCoverageFixture(tb testing.TB) (catalogDir, moduleDir, suiteDir string) {
	tb.Helper()
	root := tb.TempDir()
	catalogDir = filepath.Join(root, "catalog")
	moduleDir = filepath.Join(root, "module")
	suiteDir = filepath.Join(moduleDir, "scenarios")
	for _, dir := range []string{catalogDir, suiteDir} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			tb.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	files := map[string]string{
		filepath.Join(catalogDir, "aaa.yaml"): `feature: aaa
prefix: AAA
title: Coverage fixture
specs:
  - RFC 6749
rows:
  - id: AAA-001
    severity: P0
    spec: RFC 6749 section 1
    behaviour: The row whose only test is a skip stub.
    status: active
`,
		filepath.Join(moduleDir, "go.mod"): "module scenariofixture\n\ngo 1.25.0\n",
		filepath.Join(suiteDir, "aaa_test.go"): `package scenarios

import "testing"

func TestScenario_AAA_001_Stub(t *testing.T) {
	t.Skip("pending")
}
`,
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			tb.Fatalf("write %s: %v", path, err)
		}
	}
	return catalogDir, moduleDir, suiteDir
}

func TestClassifyCoverage(t *testing.T) {
	t.Parallel()
	catalog := map[string]rowBinding{
		"AAA-001": {status: "active"},
		"AAA-002": {status: "active"},
		"AAA-003": {status: "pending"},
		"AAA-004": {status: "out-of-scope"},
		"AAA-005": {status: "out-of-scope"},
	}
	tests := map[string]struct{}{
		"AAA-001": {}, "AAA-002": {}, "AAA-004": {}, "AAA-005": {}, "ZZZ-009": {},
	}
	stubs := map[string]struct{}{"AAA-002": {}, "AAA-004": {}}

	res := classifyCoverage(catalog, tests, stubs, nil)

	if res.bound != 1 || res.inScope != 3 {
		t.Errorf("bound=%d inScope=%d, want 1 and 3", res.bound, res.inScope)
	}
	assertIDs(t, "missingTests", res.missingTests, []string{"AAA-003"})
	assertIDs(t, "skippedBindings", res.skippedBindings, []string{"AAA-002"})
	assertIDs(t, "unboundTests", res.unboundTests, []string{"ZZZ-009"})
	// AAA-004 is out-of-scope with a stub, which is the documented
	// marker shape; AAA-005 is out-of-scope with a test that runs.
	assertIDs(t, "assertedOutOfScope", res.assertedOutOfScope, []string{"AAA-005"})
}

func TestClassifyCoverage_Delegation(t *testing.T) {
	t.Parallel()
	catalog := map[string]rowBinding{
		"AAA-001": {status: "active", coveredBy: "internal/thing.TestResolves"},
		"AAA-002": {status: "active", coveredBy: "internal/thing.TestRenamedAway"},
	}
	// Both rows keep a skip stub in the suite; neither is a skip-only
	// finding, because the row states where the assertion lives.
	tests := map[string]struct{}{"AAA-001": {}, "AAA-002": {}}
	stubs := map[string]struct{}{"AAA-001": {}, "AAA-002": {}}
	broken := map[string]string{"AAA-002": "covered_by names a test that does not exist"}

	res := classifyCoverage(catalog, tests, stubs, broken)

	if res.bound != 1 || res.delegated != 1 {
		t.Errorf("bound=%d delegated=%d, want 1 and 1", res.bound, res.delegated)
	}
	if len(res.skippedBindings) != 0 {
		t.Errorf("skippedBindings=%v, want none: a delegated row is not a stub finding", res.skippedBindings)
	}
	if len(res.brokenDelegations) != 1 {
		t.Fatalf("brokenDelegations=%v, want exactly AAA-002", res.brokenDelegations)
	}
	if !strings.HasPrefix(res.brokenDelegations[0], "AAA-002: ") {
		t.Errorf("brokenDelegations[0]=%q, want it to name AAA-002", res.brokenDelegations[0])
	}
	// A broken delegation must fail both gates: it is drift, not
	// progress.
	if !res.failing(false) || !res.failing(true) {
		t.Error("a broken delegation must fail the binding gate as well as --strict")
	}
}

func TestVerifyDelegations_UnresolvableReferences(t *testing.T) {
	t.Parallel()
	rows := map[string]rowBinding{
		"AAA-001": {status: "active", coveredBy: "malformed"},
		"AAA-002": {status: "active", coveredBy: "no/such/package.TestNothing"},
		"AAA-003": {status: "active"}, // no delegation, nothing to resolve
	}
	broken, err := verifyDelegations(t.Context(), rows, "")
	if err != nil {
		t.Fatalf("verifyDelegations returned an error; unresolvable rows are findings, not failures: %v", err)
	}
	if _, ok := broken["AAA-001"]; !ok {
		t.Error("a covered_by with no package/function separator must be reported")
	}
	// A package that cannot be listed leaves the claim unverified,
	// which is the same problem as a missing test: nothing checked it.
	if _, ok := broken["AAA-002"]; !ok {
		t.Error("a covered_by naming a package that will not build must be reported")
	}
	if _, ok := broken["AAA-003"]; ok {
		t.Error("a row without covered_by must not be reported")
	}
}

func assertIDs(tb testing.TB, label string, got, want []string) {
	tb.Helper()
	if len(got) != len(want) {
		tb.Errorf("%s = %v, want %v", label, got, want)
		return
	}
	for i := range want {
		if got[i] != want[i] {
			tb.Errorf("%s = %v, want %v", label, got, want)
			return
		}
	}
}
