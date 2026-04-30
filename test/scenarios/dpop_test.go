package scenarios_test

// Catalog: test/scenarios/catalog/dpop.yaml (DPOP-NNN)
// Spec:
//   - RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)
//   - RFC 6749 — OAuth 2.0 Authorization Framework
//   - RFC 6750 — OAuth 2.0 Bearer Token Usage
//   - OIDC Core 1.0
//   - RFC 9126 — Pushed Authorization Requests
//   - RFC 8628 — Device Authorization Grant
//   - OpenID CIBA Core 1.0

import "testing"

func TestScenario_DPOP_001_DiscoveryAdvertisesDPoPSigningAlgs(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-001")
}

func TestScenario_DPOP_002_AccessTokenRejectsDualBinding(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-002")
}

func TestScenario_DPOP_003_BearerSchemeRejectedForDPoPToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-003")
}

func TestScenario_DPOP_004_MissingProofHeaderRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-004")
}

func TestScenario_DPOP_005_TokenInFormBodyRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-005")
}

func TestScenario_DPOP_006_BearerSchemeWithDPoPHeaderRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-006")
}

func TestScenario_DPOP_007_ProofTypMustBeDpopJwt(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-007")
}

func TestScenario_DPOP_008_ProofAlgWhitelistEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-008")
}

func TestScenario_DPOP_009_ProofJwkHeaderMustBeObject(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-009")
}

func TestScenario_DPOP_010_ProofJwkMustBePublic(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-010")
}

func TestScenario_DPOP_011_ProofJwkRejectsSymmetricKey(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-011")
}

func TestScenario_DPOP_012_ProofRequiresJtiClaim(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-012")
}

func TestScenario_DPOP_013_ProofHtmMustMatchMethod(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-013")
}

func TestScenario_DPOP_014_ProofHtuMustMatchURI(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-014")
}

func TestScenario_DPOP_015_IatFreshnessWindowEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-015")
}

func TestScenario_DPOP_016_IatFailureSurfacesNonceChallenge(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-016")
}

func TestScenario_DPOP_017_ProofReplayDetected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-017")
}

func TestScenario_DPOP_018_JktVerificationAtResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-018")
}

func TestScenario_DPOP_019_JktVerificationFailsUnderBearer(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-019")
}

func TestScenario_DPOP_020_AthClaimMismatchRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-020")
}

func TestScenario_DPOP_021_AthClaimRequiredAtResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-021")
}

func TestScenario_DPOP_022_MalformedHeaderAtTokenRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-022")
}

func TestScenario_DPOP_023_InvalidNonceAtUserinfoChallenge(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-023")
}

func TestScenario_DPOP_024_InvalidNonceAtTokenChallenge(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-024")
}

func TestScenario_DPOP_025_RequiredNonceAtPAR(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-025")
}

func TestScenario_DPOP_026_RequiredNonceAtUserinfo(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-026")
}

func TestScenario_DPOP_027_RequiredNonceAtToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-027")
}

func TestScenario_DPOP_028_FreshNonceNotRotated(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-028")
}

func TestScenario_DPOP_029_IntrospectionSurfacesCnfJkt(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-029")
}

func TestScenario_DPOP_030_DeviceCodeBindingConfidential(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-030")
}

func TestScenario_DPOP_031_DeviceCodeBindingPublic(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-031")
}

func TestScenario_DPOP_032_CIBABindingConfidential(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-032")
}

func TestScenario_DPOP_033_CIBABindingPublic(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-033")
}

func TestScenario_DPOP_034_PARDpopJktMatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-034")
}

func TestScenario_DPOP_035_PARDpopJktMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-035")
}

func TestScenario_DPOP_036_PARAutoBindsDpopJkt(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-036")
}

func TestScenario_DPOP_037_PARWithRequestObjectAutoBindsJkt(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-037")
}

func TestScenario_DPOP_038_CodeGrantWithoutDpopJkt(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-038")
}

func TestScenario_DPOP_039_CodeGrantWithDpopJktMatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-039")
}

func TestScenario_DPOP_040_CodeGrantKeyMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-040")
}

func TestScenario_DPOP_041_CodeGrantRequiresProofWhenJktSet(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-041")
}

func TestScenario_DPOP_042_RefreshTokenConfidential(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-042")
}

func TestScenario_DPOP_043_CodeGrantPublicClient(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-043")
}

func TestScenario_DPOP_044_RefreshTokenPublicClientSuccess(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-044")
}

func TestScenario_DPOP_045_RefreshTokenPublicClientKeyMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-045")
}

func TestScenario_DPOP_046_ClientCredentialsBinding(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-046")
}

func TestScenario_DPOP_047_TokenEndpointErrorShape(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-047")
}

func TestScenario_DPOP_048_ResourceErrorWWWAuthenticateShape(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-048")
}

func TestScenario_DPOP_049_NonceHeaderFormat(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DPOP-049")
}
