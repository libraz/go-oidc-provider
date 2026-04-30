package scenarios_test

// Catalog: test/scenarios/catalog/end_session.yaml (ES-NNN)
// Spec:
//   - OIDC RP-Initiated Logout 1.0
//   - OIDC Core 1.0 §2, §3.1.3.7
//   - OIDC Discovery 1.0 (`end_session_endpoint`)
//   - RFC 7519 (JWT)
//   - RFC 6749 §3.1.2

import "testing"

func TestScenario_ES_001_ConfirmationFormRenderedOnGetWithoutSession(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-001")
}

func TestScenario_ES_002_ConfirmationFormRenderedOnPostWithoutSession(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-002")
}

func TestScenario_ES_003_ExpiredIDTokenHintAcceptedForLogout(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-003")
}

func TestScenario_ES_004_RedirectViaIDTokenHint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-004")
}

func TestScenario_ES_005_RedirectViaClientID(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-005")
}

func TestScenario_ES_006_RedirectViaIDTokenHintAndClientID(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-006")
}

func TestScenario_ES_007_ClientIDMismatchWithIDTokenHintRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-007")
}

func TestScenario_ES_008_UnknownClientIDRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-008")
}

func TestScenario_ES_009_HMACHintWithExpiredSecretRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-009")
}

func TestScenario_ES_010_RequestEntitiesPopulated(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-010")
}

func TestScenario_ES_011_StatePassthroughOnRequest(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-011")
}

func TestScenario_ES_012_DefaultPostLogoutRedirect(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-012")
}

func TestScenario_ES_013_UnverifiedPostLogoutRedirectURIDropped(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-013")
}

func TestScenario_ES_014_UnregisteredPostLogoutRedirectURIRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-014")
}

func TestScenario_ES_015_MalformedIDTokenHintRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-015")
}

func TestScenario_ES_016_IDTokenHintAudienceUnknownRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-016")
}

func TestScenario_ES_017_IDTokenHintSignatureInvalidRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-017")
}

func TestScenario_ES_018_ConfirmWithoutStateRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-018")
}

func TestScenario_ES_019_ConfirmXSRFMismatchRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-019")
}

func TestScenario_ES_020_ConfirmEntitiesPopulated(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-020")
}

func TestScenario_ES_021_FullSessionDestroyAndGrantRevocation(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-021")
}

func TestScenario_ES_022_PerClientLogoutWithRedirect(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-022")
}

func TestScenario_ES_023_PerClientLogoutDefaultSuccessPage(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-023")
}

func TestScenario_ES_024_StateForwardedToRP(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-024")
}

func TestScenario_ES_025_ConfirmWithoutPriorAuthorizations(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-025")
}

func TestScenario_ES_026_SuccessPageWithoutClient(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-026")
}

func TestScenario_ES_027_SuccessPageWithKnownClient(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-027")
}

func TestScenario_ES_028_SuccessPageUnknownClientRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ES-028")
}
