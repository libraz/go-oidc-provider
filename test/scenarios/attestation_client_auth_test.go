package scenarios_test

// Catalog: test/scenarios/catalog/attestation_client_auth.yaml (ATB-NNN)
// Spec:
//   - draft-ietf-oauth-attestation-based-client-auth
//   - RFC 9126 — Pushed Authorization Requests
//   - RFC 8628 — Device Authorization Grant
//   - OpenID CIBA Core 1.0
//   - RFC 7662 — OAuth 2.0 Token Introspection
//   - RFC 7009 — OAuth 2.0 Token Revocation

import "testing"

func TestScenario_ATB_001_HeadersRequired(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-001")
}

func TestScenario_ATB_002_AttestationTypMustMatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-002")
}

func TestScenario_ATB_003_AttestationAlgWhitelist(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-003")
}

func TestScenario_ATB_004_AttestationIssuerTrust(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-004")
}

func TestScenario_ATB_005_AttestationSubjectMatchesClientID(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-005")
}

func TestScenario_ATB_006_AttestationExpired(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-006")
}

func TestScenario_ATB_007_AttestationCnfJwkRequired(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-007")
}

func TestScenario_ATB_008_PopTypMustMatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-008")
}

func TestScenario_ATB_009_PopAlgWhitelist(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-009")
}

func TestScenario_ATB_010_PopIssuerEqualsClientID(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-010")
}

func TestScenario_ATB_011_PopAudienceEqualsIssuer(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-011")
}

func TestScenario_ATB_012_PopJtiUniqueness(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-012")
}

func TestScenario_ATB_013_PopSignatureKey(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-013")
}

func TestScenario_ATB_014_PopChallengeClaim(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-014")
}

func TestScenario_ATB_015_RefreshTokenIssuedWithBinding(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-015")
}

func TestScenario_ATB_016_RefreshTokenSameInstance(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-016")
}

func TestScenario_ATB_017_RefreshTokenInstanceMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-017")
}

func TestScenario_ATB_018_IntrospectionMismatchedInstance(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-018")
}

func TestScenario_ATB_019_RevocationMismatchedInstance(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-019")
}

func TestScenario_ATB_020_IntrospectionBindingInstance(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-020")
}

func TestScenario_ATB_021_RevocationBindingInstance(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-021")
}

func TestScenario_ATB_022_IntrospectionAfterRevocation(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-022")
}

func TestScenario_ATB_023_PARRequestUriBinding(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-023")
}

func TestScenario_ATB_024_PARDerivedCodeMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-024")
}

func TestScenario_ATB_025_PARDerivedCodeMatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-025")
}

func TestScenario_ATB_026_DeviceAuthorizationBinding(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-026")
}

func TestScenario_ATB_027_DeviceCodeMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-027")
}

func TestScenario_ATB_028_DeviceCodeMatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-028")
}

func TestScenario_ATB_029_CIBABackchannelBinding(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-029")
}

func TestScenario_ATB_030_CIBATokenInstanceMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-030")
}

func TestScenario_ATB_031_CIBATokenInstanceMatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-031")
}

func TestScenario_ATB_032_GrantErrorEventEmitted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ATB-032")
}
