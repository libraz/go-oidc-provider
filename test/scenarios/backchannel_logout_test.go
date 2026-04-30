package scenarios_test

// Catalog: test/scenarios/catalog/backchannel_logout.yaml (BCL-NNN)
// Spec:
//   - OIDC Back-Channel Logout 1.0
//   - OIDC Core 1.0 §2, §3.1.3.6
//   - OIDC Discovery 1.0
//   - OIDC Front-Channel Logout 1.0 / Session Management 1.0
//   - RFC 8417, RFC 7519, RFC 7515

import "testing"

func TestScenario_BCL_001_LogoutTokenShapeWithSid(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BCL-001")
}

func TestScenario_BCL_002_LogoutTokenOmitsSidWhenNotRequired(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BCL-002")
}

func TestScenario_BCL_003_DeliveryFailureSurfacedToOperators(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BCL-003")
}

func TestScenario_BCL_004_DiscoveryAdvertisesBCLSupport(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BCL-004")
}

func TestScenario_BCL_005_AuthorizeIDTokenCarriesSid(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BCL-005")
}

func TestScenario_BCL_006_CodeGrantIDTokenCarriesSid(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BCL-006")
}

func TestScenario_BCL_007_RefreshGrantIDTokenCarriesSid(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BCL-007")
}

func TestScenario_BCL_008_GlobalLogoutFansOutToVisitedClients(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BCL-008")
}

func TestScenario_BCL_009_TargetedLogoutOnlyContactsInitiator(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BCL-009")
}

func TestScenario_BCL_010_ClientWithoutBCLUriIsSkipped(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BCL-010")
}
