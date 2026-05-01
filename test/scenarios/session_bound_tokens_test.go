package scenarios_test

// Catalog: test/scenarios/catalog/session_bound_tokens.yaml (SBT-NNN)
// Spec:
//   - OIDC Core 1.0 §3, §3.2, §11
//   - RFC 6749 §1.5, §6, §10.4
//   - RFC 6750 §3
//   - OIDC Session Management 1.0

import "testing"

// TestScenario_SBT_001_CodeAccessTokenBoundToSession is OOS — see
// catalog out_of_scope_reason.
func TestScenario_SBT_001_CodeAccessTokenBoundToSession(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: SBT-001 (see catalog out_of_scope_reason)")
}

// TestScenario_SBT_002_OnlineRefreshTokenBoundToSession is OOS — see
// catalog out_of_scope_reason.
func TestScenario_SBT_002_OnlineRefreshTokenBoundToSession(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: SBT-002 (see catalog out_of_scope_reason)")
}

// TestScenario_SBT_003_OfflineAccessSurvivesSessionDestroy is OOS — see
// catalog out_of_scope_reason.
func TestScenario_SBT_003_OfflineAccessSurvivesSessionDestroy(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: SBT-003 (see catalog out_of_scope_reason)")
}

func TestScenario_SBT_004_ImplicitAccessTokenBoundToSession(t *testing.T) {
	t.Parallel()
	t.Skip("pending: SBT-004")
}
