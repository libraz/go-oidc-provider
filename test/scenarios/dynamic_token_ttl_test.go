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

// TestScenario_DTT_001_ClientCredentialsTTLApplied is OOS — see catalog out_of_scope_reason.
func TestScenario_DTT_001_ClientCredentialsTTLApplied(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DTT-001 (see catalog out_of_scope_reason)")
}

// TestScenario_DTT_002_DeviceCodeTTLApplied is OOS — see catalog out_of_scope_reason.
func TestScenario_DTT_002_DeviceCodeTTLApplied(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DTT-002 (see catalog out_of_scope_reason)")
}

// TestScenario_DTT_003_DeviceCodeExchangeInvokesTTLs is OOS — see catalog out_of_scope_reason.
func TestScenario_DTT_003_DeviceCodeExchangeInvokesTTLs(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DTT-003 (see catalog out_of_scope_reason)")
}

// TestScenario_DTT_004_HybridFlowAppliesPerKindTTL is OOS — see catalog out_of_scope_reason.
func TestScenario_DTT_004_HybridFlowAppliesPerKindTTL(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DTT-004 (see catalog out_of_scope_reason)")
}

// TestScenario_DTT_005_AuthorizationCodeGrantInvokesTTLs is OOS — see catalog out_of_scope_reason.
func TestScenario_DTT_005_AuthorizationCodeGrantInvokesTTLs(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DTT-005 (see catalog out_of_scope_reason)")
}

// TestScenario_DTT_006_RefreshGrantReinvokesTTLs is OOS — see catalog out_of_scope_reason.
func TestScenario_DTT_006_RefreshGrantReinvokesTTLs(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DTT-006 (see catalog out_of_scope_reason)")
}
