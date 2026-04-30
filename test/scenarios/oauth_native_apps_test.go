package scenarios_test

// Catalog: test/scenarios/catalog/oauth_native_apps.yaml (NA-NNN)
// Spec:
//   - RFC 8252 — OAuth 2.0 for Native Apps
//   - RFC 6749 §3.1.2, §10.6
//   - RFC 3986 — Uniform Resource Identifier
//   - OIDC Dynamic Client Registration §2 (application_type=native)
//   - OpenID Connect RP-Initiated Logout

import "testing"

func TestScenario_NA_001_MalformedRedirectURIRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-001")
}

func TestScenario_NA_002_LocalhostWithRegisteredPortAllowsAnyPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-002")
}

func TestScenario_NA_003_LocalhostWithoutPortAllowsAnyPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-003")
}

func TestScenario_NA_004_IPv4LoopbackWithRegisteredPortAllowsAnyPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-004")
}

func TestScenario_NA_005_IPv4LoopbackWithoutPortAllowsAnyPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-005")
}

func TestScenario_NA_006_IPv6LoopbackWithRegisteredPortAllowsAnyPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-006")
}

func TestScenario_NA_007_IPv6LoopbackWithoutPortAllowsAnyPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-007")
}

func TestScenario_NA_008_PostLogoutLocalhostWithRegisteredPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-008")
}

func TestScenario_NA_009_PostLogoutLocalhostWithoutPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-009")
}

func TestScenario_NA_010_PostLogoutIPv4WithRegisteredPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-010")
}

func TestScenario_NA_011_PostLogoutIPv4WithoutPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-011")
}

func TestScenario_NA_012_PostLogoutIPv6WithRegisteredPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-012")
}

func TestScenario_NA_013_PostLogoutIPv6WithoutPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-013")
}

func TestScenario_NA_014_RegistrationRejectsNonLoopbackHTTPRedirect(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-014")
}

func TestScenario_NA_015_RegistrationRejectsNonLoopbackHTTPPostLogout(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-015")
}
