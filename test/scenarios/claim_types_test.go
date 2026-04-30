package scenarios_test

// Catalog: test/scenarios/catalog/claim_types.yaml (CT-NN)
// Spec:
//   - OIDC Core 1.0 §5.6, §5.6.1, §5.6.2, §5.6.2.1, §5.6.2.2
//   - OIDC Core 1.0 §3.1.3.6 (id_token), §5.3 (UserInfo)
//   - OIDC Core 1.0 §16 (Security Considerations)

import "testing"

func TestScenario_CT_01_NormalClaimsEmbeddedDirectly(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-01")
}

func TestScenario_CT_02_ScopeProjectionWithNormalClaimsOnly(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-02")
}

func TestScenario_CT_03_NormalClaimWinsOverAggregatedOrDistributed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-03")
}

func TestScenario_CT_10_ClaimNamesShape(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-10")
}

func TestScenario_CT_11_ClaimSourcesShape(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-11")
}

func TestScenario_CT_12_ClaimNamesSourceIDMustExist(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-12")
}

func TestScenario_CT_13_ClaimNamesAndSourcesEmittedAsPair(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-13")
}

func TestScenario_CT_14_UnrequestedEntriesNotEmitted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-14")
}

func TestScenario_CT_15_NoExternalClaimsSectionOmitted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-15")
}

func TestScenario_CT_16_SourceIDReusableAcrossClaims(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-16")
}

func TestScenario_CT_20_AggregatedDescriptorJWTShape(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-20")
}

func TestScenario_CT_21_AggregatedJWTRelayedVerbatim(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-21")
}

func TestScenario_CT_22_AggregatedJWTExpectedSigned(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-22")
}

func TestScenario_CT_23_AggregatedJWTOptionalPreValidation(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-23")
}

func TestScenario_CT_30_DistributedDescriptorEndpointShape(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-30")
}

func TestScenario_CT_31_DistributedEndpointMustBeHTTPS(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-31")
}

func TestScenario_CT_32_DistributedAccessTokenRelayedVerbatim(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-32")
}

func TestScenario_CT_33_OPDoesNotFetchDistributedEndpoint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-33")
}

func TestScenario_CT_40_AccountHookExternalClaimsRelayed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-40")
}

func TestScenario_CT_41_HookNormalAndExternalNormalWins(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-41")
}

func TestScenario_CT_42_DanglingClaimNameEntryDropped(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-42")
}

func TestScenario_CT_43_DescriptorWithoutEndpointOrJWTDropped(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-43")
}

func TestScenario_CT_50_IDTokenClaimNamesScopedToIDTokenRequest(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-50")
}

func TestScenario_CT_51_UserinfoClaimNamesScopedToUserinfoRequest(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-51")
}

func TestScenario_CT_52_OpenIDOnlyOmitsExternalClaimsSection(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-52")
}

func TestScenario_CT_60_DistributedAccessTokenShortLivedScopeLimited(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-60")
}

func TestScenario_CT_61_DistributedEndpointURLValidatedByStore(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-61")
}

func TestScenario_CT_62_FeatureFlagDisablesAggregatedAndDistributed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CT-62")
}
