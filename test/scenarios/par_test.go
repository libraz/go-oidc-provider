package scenarios_test

// Catalog: test/scenarios/catalog/par.yaml (PAR-NNN)
// Spec:
//   - RFC 9126 — OAuth 2.0 Pushed Authorization Requests
//   - RFC 9101 — JWT-Secured Authorization Request (JAR)
//   - OpenID Connect Core 1.0 §3.1.2
//   - OpenID Connect Discovery 1.0 §3

import "testing"

func TestScenario_PAR_001_DiscoveryParOnly(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-001")
}

func TestScenario_PAR_002_DiscoveryRequirePAR(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-002")
}

func TestScenario_PAR_003_DiscoveryParPlusJar(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-003")
}

func TestScenario_PAR_004_UnregisteredRedirectUriConfidential(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-004")
}

func TestScenario_PAR_005_UnregisteredRedirectUriPublicRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-005")
}

func TestScenario_PAR_006_MalformedRedirectUriRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-006")
}

func TestScenario_PAR_007_RedirectUriFragmentRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-007")
}

func TestScenario_PAR_008_RequestParamRejectedInParOnly(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-008")
}

func TestScenario_PAR_009_ContextEntityExposed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-009")
}

func TestScenario_PAR_010_PlainPushSuccess(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-010")
}

func TestScenario_PAR_011_RequestUriRejectedAtPAR(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-011")
}

func TestScenario_PAR_012_UnknownRedirectUriRemapped(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-012")
}

func TestScenario_PAR_013_AdapterFailurePassthrough(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-013")
}

func TestScenario_PAR_014_RequestUriConsumedNoJAR(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-014")
}

func TestScenario_PAR_015_RequestUriConsumedWhenJAROptional(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-015")
}

func TestScenario_PAR_016_ContextEntityWithJAR(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-016")
}

func TestScenario_PAR_017_JARPushSuccess(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-017")
}

func TestScenario_PAR_018_JARDefaultExp(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-018")
}

func TestScenario_PAR_019_JARExpBelowMaxTTL(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-019")
}

func TestScenario_PAR_020_JARExpClampedToMaxTTL(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-020")
}

func TestScenario_PAR_021_JAROverridesOuterParams(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-021")
}

func TestScenario_PAR_022_PreregisteredAlgEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-022")
}

func TestScenario_PAR_023_ClientIDConsistency(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-023")
}

func TestScenario_PAR_024_RedirectUriRemapWithJAR(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-024")
}

func TestScenario_PAR_025_AdapterFailureWithJAR(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-025")
}

func TestScenario_PAR_026_RequestUriConsumedWithJAR(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-026")
}

func TestScenario_PAR_027_RequestUriLifecycleErrors(t *testing.T) {
	t.Parallel()
	t.Skip("pending: PAR-027")
}
