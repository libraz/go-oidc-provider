package scenarios_test

// Catalog: test/scenarios/catalog/claim_types.yaml (CT-NN)
// Spec:
//   - OIDC Core 1.0 §5.6, §5.6.1, §5.6.2, §5.6.2.1, §5.6.2.2
//   - OIDC Core 1.0 §3.1.3.6 (id_token), §5.3 (UserInfo)
//   - OIDC Core 1.0 §16 (Security Considerations)

import "testing"

// TestScenario_CT_01_NormalClaimsEmbeddedDirectly is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_01_NormalClaimsEmbeddedDirectly(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-01 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_02_ScopeProjectionWithNormalClaimsOnly is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_02_ScopeProjectionWithNormalClaimsOnly(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-02 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_03_NormalClaimWinsOverAggregatedOrDistributed is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_03_NormalClaimWinsOverAggregatedOrDistributed(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-03 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_10_ClaimNamesShape is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_10_ClaimNamesShape(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-10 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_11_ClaimSourcesShape is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_11_ClaimSourcesShape(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-11 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_12_ClaimNamesSourceIDMustExist is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_12_ClaimNamesSourceIDMustExist(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-12 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_13_ClaimNamesAndSourcesEmittedAsPair is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_13_ClaimNamesAndSourcesEmittedAsPair(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-13 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_14_UnrequestedEntriesNotEmitted is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_14_UnrequestedEntriesNotEmitted(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-14 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_15_NoExternalClaimsSectionOmitted is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_15_NoExternalClaimsSectionOmitted(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-15 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_16_SourceIDReusableAcrossClaims is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_16_SourceIDReusableAcrossClaims(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-16 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_20_AggregatedDescriptorJWTShape is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_20_AggregatedDescriptorJWTShape(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-20 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_21_AggregatedJWTRelayedVerbatim is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_21_AggregatedJWTRelayedVerbatim(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-21 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_22_AggregatedJWTExpectedSigned is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_22_AggregatedJWTExpectedSigned(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-22 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_23_AggregatedJWTOptionalPreValidation is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_23_AggregatedJWTOptionalPreValidation(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-23 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_30_DistributedDescriptorEndpointShape is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_30_DistributedDescriptorEndpointShape(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-30 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_31_DistributedEndpointMustBeHTTPS is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_31_DistributedEndpointMustBeHTTPS(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-31 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_32_DistributedAccessTokenRelayedVerbatim is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_32_DistributedAccessTokenRelayedVerbatim(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-32 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_33_OPDoesNotFetchDistributedEndpoint is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_33_OPDoesNotFetchDistributedEndpoint(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-33 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_40_AccountHookExternalClaimsRelayed is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_40_AccountHookExternalClaimsRelayed(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-40 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_41_HookNormalAndExternalNormalWins is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_41_HookNormalAndExternalNormalWins(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-41 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_42_DanglingClaimNameEntryDropped is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_42_DanglingClaimNameEntryDropped(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-42 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_43_DescriptorWithoutEndpointOrJWTDropped is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_43_DescriptorWithoutEndpointOrJWTDropped(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-43 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_50_IDTokenClaimNamesScopedToIDTokenRequest is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_50_IDTokenClaimNamesScopedToIDTokenRequest(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-50 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_51_UserinfoClaimNamesScopedToUserinfoRequest is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_51_UserinfoClaimNamesScopedToUserinfoRequest(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-51 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_52_OpenIDOnlyOmitsExternalClaimsSection is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_52_OpenIDOnlyOmitsExternalClaimsSection(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-52 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_60_DistributedAccessTokenShortLivedScopeLimited is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_60_DistributedAccessTokenShortLivedScopeLimited(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-60 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_61_DistributedEndpointURLValidatedByStore is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_61_DistributedEndpointURLValidatedByStore(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-61 (see catalog out_of_scope_reason)")
}

// TestScenario_CT_62_FeatureFlagDisablesAggregatedAndDistributed is OOS — see catalog out_of_scope_reason.
func TestScenario_CT_62_FeatureFlagDisablesAggregatedAndDistributed(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CT-62 (see catalog out_of_scope_reason)")
}
