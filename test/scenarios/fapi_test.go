package scenarios_test

// Catalog: test/scenarios/catalog/fapi.yaml (FAPI-NNN, FAPI-V1-NNN, FAPI-V2-NNN)
// Spec:
//   - FAPI 1.0 Part 2 (Advanced) — Final
//   - FAPI 2.0 Security Profile — Final
//   - FAPI 2.0 Message Signing
//   - RFC 9101 — JAR / Request Object
//   - RFC 9126 — PAR
//   - RFC 6749 §3.2.1, §10
//   - RFC 9700 — OAuth 2.0 Security Best Current Practice
//   - RFC 8707 — Resource Indicators
//   - OIDC Core 1.0 §3.2 (hybrid), §15.5 (sender-constrained tokens)

import "testing"

func TestScenario_FAPI_001_UserInfoRejectsQueryAccessToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: FAPI-001")
}

func TestScenario_FAPI_002_AuthorizationRejectsBadResponseMode(t *testing.T) {
	t.Parallel()
	t.Skip("pending: FAPI-002")
}

// TestScenario_FAPI_V1_010_HybridAcceptsNoPKCEWithIDToken is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_V1_010_HybridAcceptsNoPKCEWithIDToken(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-V1-010 (see catalog out_of_scope_reason)")
}

// TestScenario_FAPI_V1_011_PARRequiresPKCE is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_V1_011_PARRequiresPKCE(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-V1-011 (see catalog out_of_scope_reason)")
}

// TestScenario_FAPI_V1_012_CodeOnlyRequiresJARM is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_V1_012_CodeOnlyRequiresJARM(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-V1-012 (see catalog out_of_scope_reason)")
}

// TestScenario_FAPI_V1_013_JARRequestRequiresJARM is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_V1_013_JARRequestRequiresJARM(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-V1-013 (see catalog out_of_scope_reason)")
}

// TestScenario_FAPI_V1_014_RequestObjectRequiresExp is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_V1_014_RequestObjectRequiresExp(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-V1-014 (see catalog out_of_scope_reason)")
}

// TestScenario_FAPI_V1_015_RequestObjectRequiresNbf is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_V1_015_RequestObjectRequiresNbf(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-V1-015 (see catalog out_of_scope_reason)")
}

// TestScenario_FAPI_V1_016_RequestObjectExpNbfWindow is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_V1_016_RequestObjectExpNbfWindow(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-V1-016 (see catalog out_of_scope_reason)")
}

// TestScenario_FAPI_V1_017_HybridSignedRequestProducesIDToken is OOS — see catalog out_of_scope_reason.
func TestScenario_FAPI_V1_017_HybridSignedRequestProducesIDToken(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: FAPI-V1-017 (see catalog out_of_scope_reason)")
}

func TestScenario_FAPI_V2_020_CodeFlowRequiresPKCE(t *testing.T) {
	t.Parallel()
	t.Skip("pending: FAPI-V2-020")
}

func TestScenario_FAPI_V2_021_PrivateKeyJWTAudIsIssuer(t *testing.T) {
	t.Parallel()
	t.Skip("pending: FAPI-V2-021")
}

func TestScenario_FAPI_V2_022_RedirectURIAlwaysRequired(t *testing.T) {
	t.Parallel()
	t.Skip("pending: FAPI-V2-022")
}

func TestScenario_FAPI_V2_023_RequestObjectRequiresExpAndNbf(t *testing.T) {
	t.Parallel()
	t.Skip("pending: FAPI-V2-023")
}

func TestScenario_FAPI_V2_024_RequestObjectExpNbfWindow(t *testing.T) {
	t.Parallel()
	t.Skip("pending: FAPI-V2-024")
}

func TestScenario_FAPI_V2_025_CodePKCEProducesQueryRedirect(t *testing.T) {
	t.Parallel()
	t.Skip("pending: FAPI-V2-025")
}

func TestScenario_FAPI_030_PolicyEnforcedRegardlessOfMetadata(t *testing.T) {
	t.Parallel()
	t.Skip("pending: FAPI-030")
}

func TestScenario_FAPI_031_DetachedSignatureCarriesSHashCHash(t *testing.T) {
	t.Parallel()
	t.Skip("pending: FAPI-031")
}
