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

func TestScenario_CIBA_001_DiscoveryAdvertisesCIBAMetadata(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-001")
}

func TestScenario_CIBA_002_DiscoveryAdvertisesSignedRequestAlgs(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-002")
}

func TestScenario_CIBA_003_BackchannelResultResolvesRequestJTI(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-003")
}

func TestScenario_CIBA_004_BackchannelResultAcceptsTypedRequest(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-004")
}

func TestScenario_CIBA_005_BackchannelResultRejectsInvalidRequestType(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-005")
}

func TestScenario_CIBA_006_BackchannelResultResolvesGrantJTI(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-006")
}

func TestScenario_CIBA_007_BackchannelResultRejectsInvalidResultType(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-007")
}

func TestScenario_CIBA_008_BackchannelResultRejectsUnknownClient(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-008")
}

func TestScenario_CIBA_009_BackchannelResultRejectsClientMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-009")
}

func TestScenario_CIBA_010_BackchannelResultRejectsAccountMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-010")
}

func TestScenario_CIBA_011_BackchannelResultPersistsUnsavedRequest(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-011")
}

func TestScenario_CIBA_012_PingDeliverySuccess204(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-012")
}

func TestScenario_CIBA_013_PingDeliverySuccess200(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-013")
}

func TestScenario_CIBA_014_PingDeliveryFailure400(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-014")
}

func TestScenario_CIBA_015_BackchannelHappyPathWithLoginHint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-015")
}

func TestScenario_CIBA_016_BackchannelBypassesPARRequirement(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-016")
}

func TestScenario_CIBA_017_RequestedExpiryIsHonoured(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-017")
}

func TestScenario_CIBA_018_BackchannelHappyPathWithLoginHintToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-018")
}

func TestScenario_CIBA_019_BackchannelHappyPathWithIDTokenHint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-019")
}

func TestScenario_CIBA_020_BackchannelRequiresGrantTypeAllowance(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-020")
}

func TestScenario_CIBA_021_BackchannelRejectsUnknownClient(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-021")
}

func TestScenario_CIBA_022_BackchannelRejectsNonFormBody(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-022")
}

func TestScenario_CIBA_023_BackchannelRejectsRequestWithoutJAR(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-023")
}

func TestScenario_CIBA_024_BackchannelRejectsRequestURI(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-024")
}

func TestScenario_CIBA_025_BackchannelRejectsRegistration(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-025")
}

func TestScenario_CIBA_026_BackchannelRejectsUnknownLoginHint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-026")
}

func TestScenario_CIBA_027_BackchannelRejectsUnknownLoginHintToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-027")
}

func TestScenario_CIBA_028_BackchannelRequiresScope(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-028")
}

func TestScenario_CIBA_029_PingRequiresClientNotificationToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-029")
}

func TestScenario_CIBA_030_BackchannelRequiresOpenIDScope(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-030")
}

func TestScenario_CIBA_031_BackchannelValidatesRequestedExpiry(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-031")
}

func TestScenario_CIBA_032_BackchannelRequiresAtLeastOneHint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-032")
}

func TestScenario_CIBA_033_BackchannelRejectsMultipleHints(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-033")
}

func TestScenario_CIBA_034_BackchannelRejectsRequestParamWithoutJAR(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-034")
}

func TestScenario_CIBA_035_BackchannelRejectsRequestURIWithJAR(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-035")
}

func TestScenario_CIBA_036_BackchannelRejectsRegistrationWithJAR(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-036")
}

func TestScenario_CIBA_037_BackchannelRequiresSignedRequestObject(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-037")
}

func TestScenario_CIBA_038_RequestObjectRequiresExpClaim(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-038")
}

func TestScenario_CIBA_039_RequestObjectRequiresNbfClaim(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-039")
}

func TestScenario_CIBA_040_RequestObjectRequiresJtiClaim(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-040")
}

func TestScenario_CIBA_041_RequestObjectRequiresIatClaim(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-041")
}

func TestScenario_CIBA_042_BackchannelRejectsEncryptedRequestObject(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CIBA-042")
}
