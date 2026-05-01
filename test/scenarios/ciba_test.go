package scenarios_test

// Catalog: test/scenarios/catalog/ciba.yaml (CIBA-NNN)
// Spec:
//   - OpenID Connect Client-Initiated Backchannel Authentication Flow — Core 1.0
//   - OpenID Connect Discovery 1.0 §3 (CIBA metadata)
//   - RFC 9126 — Pushed Authorization Requests (interaction with CIBA)
//   - RFC 9101 — JWT-Secured Authorization Request
//   - FAPI-CIBA Profile
//   - RFC 6749 §5.2 — Error response
//   - RFC 7519 §4.1 — Registered JWT claims

import "testing"

// TestScenario_CIBA_001_DiscoveryAdvertisesCIBAMetadata is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_001_DiscoveryAdvertisesCIBAMetadata(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-001 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_002_DiscoveryAdvertisesSignedRequestAlgs is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_002_DiscoveryAdvertisesSignedRequestAlgs(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-002 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_003_BackchannelResultResolvesRequestJTI is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_003_BackchannelResultResolvesRequestJTI(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-003 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_004_BackchannelResultAcceptsTypedRequest is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_004_BackchannelResultAcceptsTypedRequest(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-004 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_005_BackchannelResultRejectsInvalidRequestType is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_005_BackchannelResultRejectsInvalidRequestType(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-005 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_006_BackchannelResultResolvesGrantJTI is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_006_BackchannelResultResolvesGrantJTI(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-006 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_007_BackchannelResultRejectsInvalidResultType is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_007_BackchannelResultRejectsInvalidResultType(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-007 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_008_BackchannelResultRejectsUnknownClient is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_008_BackchannelResultRejectsUnknownClient(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-008 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_009_BackchannelResultRejectsClientMismatch is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_009_BackchannelResultRejectsClientMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-009 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_010_BackchannelResultRejectsAccountMismatch is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_010_BackchannelResultRejectsAccountMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-010 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_011_BackchannelResultPersistsUnsavedRequest is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_011_BackchannelResultPersistsUnsavedRequest(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-011 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_012_PingDeliverySuccess204 is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_012_PingDeliverySuccess204(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-012 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_013_PingDeliverySuccess200 is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_013_PingDeliverySuccess200(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-013 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_014_PingDeliveryFailure400 is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_014_PingDeliveryFailure400(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-014 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_015_BackchannelHappyPathWithLoginHint is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_015_BackchannelHappyPathWithLoginHint(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-015 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_016_BackchannelBypassesPARRequirement is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_016_BackchannelBypassesPARRequirement(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-016 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_017_RequestedExpiryIsHonoured is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_017_RequestedExpiryIsHonoured(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-017 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_018_BackchannelHappyPathWithLoginHintToken is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_018_BackchannelHappyPathWithLoginHintToken(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-018 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_019_BackchannelHappyPathWithIDTokenHint is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_019_BackchannelHappyPathWithIDTokenHint(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-019 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_020_BackchannelRequiresGrantTypeAllowance is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_020_BackchannelRequiresGrantTypeAllowance(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-020 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_021_BackchannelRejectsUnknownClient is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_021_BackchannelRejectsUnknownClient(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-021 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_022_BackchannelRejectsNonFormBody is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_022_BackchannelRejectsNonFormBody(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-022 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_023_BackchannelRejectsRequestWithoutJAR is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_023_BackchannelRejectsRequestWithoutJAR(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-023 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_024_BackchannelRejectsRequestURI is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_024_BackchannelRejectsRequestURI(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-024 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_025_BackchannelRejectsRegistration is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_025_BackchannelRejectsRegistration(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-025 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_026_BackchannelRejectsUnknownLoginHint is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_026_BackchannelRejectsUnknownLoginHint(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-026 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_027_BackchannelRejectsUnknownLoginHintToken is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_027_BackchannelRejectsUnknownLoginHintToken(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-027 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_028_BackchannelRequiresScope is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_028_BackchannelRequiresScope(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-028 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_029_PingRequiresClientNotificationToken is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_029_PingRequiresClientNotificationToken(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-029 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_030_BackchannelRequiresOpenIDScope is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_030_BackchannelRequiresOpenIDScope(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-030 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_031_BackchannelValidatesRequestedExpiry is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_031_BackchannelValidatesRequestedExpiry(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-031 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_032_BackchannelRequiresAtLeastOneHint is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_032_BackchannelRequiresAtLeastOneHint(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-032 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_033_BackchannelRejectsMultipleHints is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_033_BackchannelRejectsMultipleHints(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-033 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_034_BackchannelRejectsRequestParamWithoutJAR is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_034_BackchannelRejectsRequestParamWithoutJAR(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-034 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_035_BackchannelRejectsRequestURIWithJAR is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_035_BackchannelRejectsRequestURIWithJAR(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-035 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_036_BackchannelRejectsRegistrationWithJAR is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_036_BackchannelRejectsRegistrationWithJAR(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-036 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_037_BackchannelRequiresSignedRequestObject is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_037_BackchannelRequiresSignedRequestObject(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-037 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_038_RequestObjectRequiresExpClaim is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_038_RequestObjectRequiresExpClaim(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-038 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_039_RequestObjectRequiresNbfClaim is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_039_RequestObjectRequiresNbfClaim(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-039 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_040_RequestObjectRequiresJtiClaim is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_040_RequestObjectRequiresJtiClaim(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-040 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_041_RequestObjectRequiresIatClaim is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_041_RequestObjectRequiresIatClaim(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-041 (see catalog out_of_scope_reason)")
}

// TestScenario_CIBA_042_BackchannelRejectsEncryptedRequestObject is OOS — see catalog out_of_scope_reason.
func TestScenario_CIBA_042_BackchannelRejectsEncryptedRequestObject(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CIBA-042 (see catalog out_of_scope_reason)")
}
