package scenarios_test

// Catalog: test/scenarios/catalog/id_token_claims.yaml (IDT-NN)
// Spec:
//   - OIDC Core 1.0 §2, §3.1.3.6, §3.1.3.7
//   - OIDC Core 1.0 §3.2.2.10 (at_hash), §3.3.2.10 (c_hash)
//   - OIDC Core 1.0 §5.3, §5.4, §5.5, §10, §16.11
//   - OIDC Front-Channel Logout 1.0 §2.2, OIDC Back-Channel Logout 1.0 §2.4
//   - JARM §4.2 (s_hash)
//   - RFC 9068 — JWT access token profile

import "testing"

func TestScenario_IDT_01_MandatoryClaimsPresent(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-01")
}

func TestScenario_IDT_02_AudContainsClientID(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-02")
}

func TestScenario_IDT_03_AzpSetWhenAudMultiOrRequired(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-03")
}

func TestScenario_IDT_04_NonceMirroredFromRequest(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-04")
}

func TestScenario_IDT_05_AuthTimeIncludedWhenEssentialOrMaxAge(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-05")
}

func TestScenario_IDT_06_AcrEmittedOnRequestOrDefault(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-06")
}

func TestScenario_IDT_07_AmrVoluntarilyEmitted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-07")
}

func TestScenario_IDT_08_IssMatchesDiscovery(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-08")
}

func TestScenario_IDT_10_ConformTrueExcludesScopeClaimsWithAT(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-10")
}

func TestScenario_IDT_11_ConformTrueIncludesScopeClaimsWhenIDTokenOnly(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-11")
}

func TestScenario_IDT_12_ConformFalseAlwaysIncludesScopeClaims(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-12")
}

func TestScenario_IDT_13_HybridFlowExcludesScopeClaims(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-13")
}

func TestScenario_IDT_14_ClaimsParameterAlwaysProjectedToIDToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-14")
}

func TestScenario_IDT_15_RefreshGrantUsesSameComposition(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-15")
}

func TestScenario_IDT_16_TokenEndpointUsesSameComposition(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-16")
}

func TestScenario_IDT_17_RejectedClaimsExcluded(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-17")
}

func TestScenario_IDT_20_AtHashRequiredWhenIDTokenAndATIssued(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-20")
}

func TestScenario_IDT_21_AtHashComputation(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-21")
}

func TestScenario_IDT_22_CHashRequiredWhenIDTokenAndCodeIssued(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-22")
}

func TestScenario_IDT_23_CHashComputation(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-23")
}

func TestScenario_IDT_24_SHashOptionalUnderJARM(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-24")
}

func TestScenario_IDT_25_TokenEndpointIDTokenOmitsHashes(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-25")
}

func TestScenario_IDT_26_HashAlgFollowsSigningAlg(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-26")
}

func TestScenario_IDT_27_NoneAlgOmitsHashClaims(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-27")
}

func TestScenario_IDT_30_AudShapeAndContents(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-30")
}

func TestScenario_IDT_31_SingleAudAllowsAzpOmission(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-31")
}

func TestScenario_IDT_32_MultiAudRequiresAzp(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-32")
}

func TestScenario_IDT_33_SidIncludedForLogoutSubscribers(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-33")
}

func TestScenario_IDT_34_ResourceAudienceNotInIDToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-34")
}

func TestScenario_IDT_40_LifetimeFollowsClientMetadata(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-40")
}

func TestScenario_IDT_41_SignedWithClientAlgDefaultRS256(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-41")
}

func TestScenario_IDT_42_SignedThenEncryptedWhenConfigured(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-42")
}

func TestScenario_IDT_43_SymmetricAlgUsesClientSecret(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-43")
}

func TestScenario_IDT_44_DistinctTypForIDTokenAndATJWT(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-44")
}

func TestScenario_IDT_50_UserinfoReturnsScopeClaims(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-50")
}

func TestScenario_IDT_51_UserinfoReleasesClaimsParameterEntries(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-51")
}

func TestScenario_IDT_52_SignedUserinfoResponse(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-52")
}

func TestScenario_IDT_53_EncryptedUserinfoResponse(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-53")
}

func TestScenario_IDT_54_UserinfoAlwaysIncludesSub(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-54")
}

func TestScenario_IDT_55_UserinfoSubMatchesAccessTokenSubject(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-55")
}

func TestScenario_IDT_60_NoUnsolicitedSensitiveDataEmbedded(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-60")
}

func TestScenario_IDT_61_IatReadFromInternalClock(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-61")
}

func TestScenario_IDT_62_IssNeverDeviatesFromDiscovery(t *testing.T) {
	t.Parallel()
	t.Skip("pending: IDT-62")
}
