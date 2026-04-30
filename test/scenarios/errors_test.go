package scenarios_test

// Catalog: test/scenarios/catalog/errors.yaml (ERR-NNN)
// Spec:
//   - RFC 6749 §5.2 — Error Response
//   - RFC 7807 — Problem Details (informational)
//   - OIDC Core 1.0 §3.1.2.6 — Authentication Error Response
//   - OIDC Core 1.0 §16.5 — Native Apps / non-redirect errors
//   - RFC 7235 — HTTP Authentication (WWW-Authenticate)
//   - RFC 9207 — iss parameter on errors
//   - RFC 6750 §3 — Bearer authentication challenge

import "testing"

func TestScenario_ERR_001_NoAcceptHeaderProducesJSON(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-001")
}

func TestScenario_ERR_002_AcceptStarSlashStarProducesJSON(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-002")
}

func TestScenario_ERR_003_BrowserAcceptProducesHTML(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-003")
}

func TestScenario_ERR_010_JSONErrorBodyHasErrorCode(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-010")
}

func TestScenario_ERR_011_ErrorURIOmittedByDefault(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-011")
}

func TestScenario_ERR_012_JSONErrorOmitsState(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-012")
}

func TestScenario_ERR_020_BearerEndpointEmitsWWWAuthenticate(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-020")
}

func TestScenario_ERR_021_BasicAuthFailureEmitsWWWAuthenticate(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-021")
}

func TestScenario_ERR_022_CORSExposesWWWAuthenticate(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-022")
}

func TestScenario_ERR_030_HTMLErrorPathReachableViaHook(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-030")
}

func TestScenario_ERR_031_ErrorPageHTMLEscapesValues(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-031")
}

func TestScenario_ERR_032_ErrorCatalogIsSingleSourceOfTruth(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-032")
}

func TestScenario_ERR_040_UncaughtExceptionsBecomeServerError(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-040")
}

func TestScenario_ERR_050_AuthorizationErrorRedirectIncludesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-050")
}
