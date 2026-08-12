package main

import (
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
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x_test.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	stubs, err := discoverSkipStubs(dir)
	if err != nil {
		t.Fatalf("discoverSkipStubs: %v", err)
	}
	if _, ok := stubs["AAA-001"]; !ok {
		t.Error("AAA-001 should be a skip stub")
	}
	for _, id := range []string{"AAA-002", "AAA-003", "AAA-004"} {
		if _, ok := stubs[id]; ok {
			t.Errorf("%s should not be a skip stub", id)
		}
	}
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
