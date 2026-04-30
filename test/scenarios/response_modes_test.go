package scenarios_test

// Catalog: test/scenarios/catalog/response_modes.yaml (RMO-NNN)
// Spec:
//   - OAuth 2.0 Multiple Response Type Encoding Practices §2 (response_mode)
//   - OAuth 2.0 Form Post Response Mode (Final)
//   - OAuth 2.0 Web Message Response Mode (draft, deprecated)
//   - OIDC Core 1.0 §3.1.2 (response_mode default selection)
//   - RFC 9207 — Authorization Server Issuer Identification

import "testing"

func TestScenario_RMO_001_FormPostSuccessRendersSelfSubmittingForm(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-001")
}

func TestScenario_RMO_002_FormPostHTMLEscapesRedirectURI(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-002")
}

func TestScenario_RMO_003_FormPostErrorPathRendersForm(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-003")
}

func TestScenario_RMO_004_FormPostGetAndPostBehaveIdentically(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-004")
}

func TestScenario_RMO_010_WebMessageSuccessRendersHTMLEnvelope(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-010")
}

func TestScenario_RMO_011_WebMessageIncludesStandardFields(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-011")
}

func TestScenario_RMO_012_WebMessageRelayModeRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-012")
}

func TestScenario_RMO_013_WebMessageStripsFramingHeaders(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-013")
}

func TestScenario_RMO_014_WebMessageErrorRendersEnvelope(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-014")
}

func TestScenario_RMO_020_DiscoveryAdvertisesWebMessage(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-020")
}

func TestScenario_RMO_030_RegisterResponseModeHookExposed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-030")
}

func TestScenario_RMO_031_CustomModeInvokedForSuccess(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-031")
}

func TestScenario_RMO_032_CustomModeInvokedForError(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-032")
}

func TestScenario_RMO_033_UnknownResponseModeRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-033")
}

func TestScenario_RMO_040_DefaultResponseModeSelection(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-040")
}
