package scenarios_test

// Catalog: test/scenarios/catalog/dynamic_token_ttl.yaml (DTT-NNN)
// Spec:
//   - RFC 6749 §4.4 — Client Credentials
//   - RFC 6749 §5.1 — expires_in
//   - RFC 6749 §6 — Refresh Token
//   - RFC 8628 — Device Authorization Grant
//   - OIDC Core 1.0 §3.1 — Authorization Code Flow
//   - OIDC Core 1.0 §2 — ID Token exp/iat

import "testing"

func TestScenario_DTT_001_ClientCredentialsTTLApplied(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DTT-001")
}

func TestScenario_DTT_002_DeviceCodeTTLApplied(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DTT-002")
}

func TestScenario_DTT_003_DeviceCodeExchangeInvokesTTLs(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DTT-003")
}

func TestScenario_DTT_004_HybridFlowAppliesPerKindTTL(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DTT-004")
}

func TestScenario_DTT_005_AuthorizationCodeGrantInvokesTTLs(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DTT-005")
}

func TestScenario_DTT_006_RefreshGrantReinvokesTTLs(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DTT-006")
}
