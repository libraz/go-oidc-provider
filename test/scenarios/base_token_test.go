package scenarios_test

// Catalog: test/scenarios/catalog/base_token.yaml (BT-NNN)
// Spec:
//   - RFC 6749 §6 / §10.5 — Refresh tokens / TTL
//   - OIDC Core 1.0 §3.1 — Authorization code
//   - RFC 8628 — Device Authorization Grant
//   - RFC 9068 — Contrast with structured JWT access tokens

import "testing"

// TestScenario_BT_001_LegacyStructuredTokenNotResolvable is OOS — see catalog out_of_scope_reason.
func TestScenario_BT_001_LegacyStructuredTokenNotResolvable(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BT-001 (see catalog out_of_scope_reason)")
}

// TestScenario_BT_002_ExpiredRefreshTokenReturnsNothing is OOS — see catalog out_of_scope_reason.
func TestScenario_BT_002_ExpiredRefreshTokenReturnsNothing(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BT-002 (see catalog out_of_scope_reason)")
}

// TestScenario_BT_003_FindRobustToBogusInputs is OOS — see catalog out_of_scope_reason.
func TestScenario_BT_003_FindRobustToBogusInputs(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BT-003 (see catalog out_of_scope_reason)")
}

// TestScenario_BT_004_ConsumedFlagSurvivesRoundTrip is OOS — see catalog out_of_scope_reason.
func TestScenario_BT_004_ConsumedFlagSurvivesRoundTrip(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BT-004 (see catalog out_of_scope_reason)")
}

// TestScenario_BT_005_DefaultRefreshTokenTTLIsFourteenDays is OOS — see catalog out_of_scope_reason.
func TestScenario_BT_005_DefaultRefreshTokenTTLIsFourteenDays(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BT-005 (see catalog out_of_scope_reason)")
}

// TestScenario_BT_006_ExplicitExpiresInPropagatesToAdapter is OOS — see catalog out_of_scope_reason.
func TestScenario_BT_006_ExplicitExpiresInPropagatesToAdapter(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BT-006 (see catalog out_of_scope_reason)")
}

// TestScenario_BT_007_ResaveRetainsRemainingTTL is OOS — see catalog out_of_scope_reason.
func TestScenario_BT_007_ResaveRetainsRemainingTTL(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BT-007 (see catalog out_of_scope_reason)")
}

// TestScenario_BT_008_SaveResultJTIStableAcrossMutations is OOS — see catalog out_of_scope_reason.
func TestScenario_BT_008_SaveResultJTIStableAcrossMutations(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BT-008 (see catalog out_of_scope_reason)")
}

// TestScenario_BT_009_SessionLookupExceptionRethrown is OOS — see catalog out_of_scope_reason.
func TestScenario_BT_009_SessionLookupExceptionRethrown(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BT-009 (see catalog out_of_scope_reason)")
}

// TestScenario_BT_010_ConsumedAuthorizationCodeRoundTrip is OOS — see catalog out_of_scope_reason.
func TestScenario_BT_010_ConsumedAuthorizationCodeRoundTrip(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BT-010 (see catalog out_of_scope_reason)")
}

// TestScenario_BT_011_DeviceCodeFindByUserCodeRethrows is OOS — see catalog out_of_scope_reason.
func TestScenario_BT_011_DeviceCodeFindByUserCodeRethrows(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BT-011 (see catalog out_of_scope_reason)")
}
