package scenarios_test

// Catalog: test/scenarios/catalog/session_bound_tokens.yaml (SBT-NNN)
// Spec:
//   - OIDC Core 1.0 §3, §3.2, §11
//   - RFC 6749 §1.5, §6, §10.4
//   - RFC 6750 §3
//   - OIDC Session Management 1.0

import "testing"

func TestScenario_SBT_001_CodeAccessTokenBoundToSession(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SBT-001")
}

func TestScenario_SBT_002_OnlineRefreshTokenBoundToSession(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SBT-002")
}

func TestScenario_SBT_003_OfflineAccessSurvivesSessionDestroy(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SBT-003")
}

func TestScenario_SBT_004_ImplicitAccessTokenBoundToSession(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SBT-004")
}
