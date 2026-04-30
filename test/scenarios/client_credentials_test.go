package scenarios_test

// Catalog: test/scenarios/catalog/client_credentials.yaml (CC-NNN)
// Spec:
//   - RFC 6749 §4.4 — Client Credentials Grant
//   - RFC 6749 §3.3 — Access Token Scope
//   - RFC 6749 §5.1 / §5.2 — Token Response & Error Format
//   - RFC 6750 — Bearer Token Usage

import "testing"

func TestScenario_CC_001_ConfidentialClientGetsAccessToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CC-001")
}

func TestScenario_CC_002_UnsupportedScopeNarrowedSilently(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CC-002")
}

func TestScenario_CC_003_DisallowedScopeRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CC-003")
}

func TestScenario_CC_004_EntitiesOmitAccountAndGrant(t *testing.T) {
	t.Parallel()
	t.Skip("pending: CC-004")
}
