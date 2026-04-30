package scenarios_test

// Catalog: test/scenarios/catalog/base_token.yaml (BT-NNN)
// Spec:
//   - RFC 6749 §6 / §10.5 — Refresh tokens / TTL
//   - OIDC Core 1.0 §3.1 — Authorization code
//   - RFC 8628 — Device Authorization Grant
//   - RFC 9068 — Contrast with structured JWT access tokens

import "testing"

func TestScenario_BT_001_LegacyStructuredTokenNotResolvable(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BT-001")
}

func TestScenario_BT_002_ExpiredRefreshTokenReturnsNothing(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BT-002")
}

func TestScenario_BT_003_FindRobustToBogusInputs(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BT-003")
}

func TestScenario_BT_004_ConsumedFlagSurvivesRoundTrip(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BT-004")
}

func TestScenario_BT_005_DefaultRefreshTokenTTLIsFourteenDays(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BT-005")
}

func TestScenario_BT_006_ExplicitExpiresInPropagatesToAdapter(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BT-006")
}

func TestScenario_BT_007_ResaveRetainsRemainingTTL(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BT-007")
}

func TestScenario_BT_008_SaveResultJTIStableAcrossMutations(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BT-008")
}

func TestScenario_BT_009_SessionLookupExceptionRethrown(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BT-009")
}

func TestScenario_BT_010_ConsumedAuthorizationCodeRoundTrip(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BT-010")
}

func TestScenario_BT_011_DeviceCodeFindByUserCodeRethrows(t *testing.T) {
	t.Parallel()
	t.Skip("pending: BT-011")
}
