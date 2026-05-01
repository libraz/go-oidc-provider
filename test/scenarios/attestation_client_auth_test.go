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

// TestScenario_ATB_001_HeadersRequired is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_001_HeadersRequired(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-001 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_002_AttestationTypMustMatch is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_002_AttestationTypMustMatch(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-002 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_003_AttestationAlgWhitelist is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_003_AttestationAlgWhitelist(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-003 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_004_AttestationIssuerTrust is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_004_AttestationIssuerTrust(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-004 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_005_AttestationSubjectMatchesClientID is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_005_AttestationSubjectMatchesClientID(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-005 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_006_AttestationExpired is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_006_AttestationExpired(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-006 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_007_AttestationCnfJwkRequired is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_007_AttestationCnfJwkRequired(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-007 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_008_PopTypMustMatch is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_008_PopTypMustMatch(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-008 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_009_PopAlgWhitelist is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_009_PopAlgWhitelist(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-009 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_010_PopIssuerEqualsClientID is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_010_PopIssuerEqualsClientID(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-010 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_011_PopAudienceEqualsIssuer is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_011_PopAudienceEqualsIssuer(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-011 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_012_PopJtiUniqueness is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_012_PopJtiUniqueness(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-012 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_013_PopSignatureKey is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_013_PopSignatureKey(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-013 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_014_PopChallengeClaim is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_014_PopChallengeClaim(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-014 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_015_RefreshTokenIssuedWithBinding is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_015_RefreshTokenIssuedWithBinding(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-015 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_016_RefreshTokenSameInstance is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_016_RefreshTokenSameInstance(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-016 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_017_RefreshTokenInstanceMismatch is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_017_RefreshTokenInstanceMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-017 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_018_IntrospectionMismatchedInstance is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_018_IntrospectionMismatchedInstance(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-018 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_019_RevocationMismatchedInstance is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_019_RevocationMismatchedInstance(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-019 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_020_IntrospectionBindingInstance is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_020_IntrospectionBindingInstance(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-020 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_021_RevocationBindingInstance is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_021_RevocationBindingInstance(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-021 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_022_IntrospectionAfterRevocation is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_022_IntrospectionAfterRevocation(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-022 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_023_PARRequestUriBinding is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_023_PARRequestUriBinding(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-023 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_024_PARDerivedCodeMismatch is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_024_PARDerivedCodeMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-024 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_025_PARDerivedCodeMatch is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_025_PARDerivedCodeMatch(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-025 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_026_DeviceAuthorizationBinding is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_026_DeviceAuthorizationBinding(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-026 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_027_DeviceCodeMismatch is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_027_DeviceCodeMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-027 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_028_DeviceCodeMatch is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_028_DeviceCodeMatch(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-028 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_029_CIBABackchannelBinding is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_029_CIBABackchannelBinding(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-029 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_030_CIBATokenInstanceMismatch is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_030_CIBATokenInstanceMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-030 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_031_CIBATokenInstanceMatch is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_031_CIBATokenInstanceMatch(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-031 (see catalog out_of_scope_reason)")
}

// TestScenario_ATB_032_GrantErrorEventEmitted is OOS — see catalog out_of_scope_reason.
func TestScenario_ATB_032_GrantErrorEventEmitted(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ATB-032 (see catalog out_of_scope_reason)")
}
