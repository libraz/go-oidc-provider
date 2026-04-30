package scenarios_test

// Catalog: test/scenarios/catalog/refresh.yaml (REF-NNN)
// Spec:
//   - RFC 6749 §6 — Refreshing an Access Token
//   - RFC 6749 §5.1 / §5.2 — Successful and Error Response
//   - RFC 6749 §10.4 — Refresh Token Security
//   - OIDC Core 1.0 §11 — Offline Access
//   - OIDC Core 1.0 §12 — Using Refresh Tokens
//   - RFC 9700 §4.13 — Refresh Token Replay
//   - RFC 9700 §4.14 — Refresh Token Rotation

import "testing"

func TestScenario_REF_001_NonRotatingRefreshSuccess(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-001")
}

func TestScenario_REF_002_NonRotatingRefreshEntities(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-002")
}

func TestScenario_REF_003_ExpiredRefreshTokenRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-003")
}

func TestScenario_REF_004_RefreshClientMismatchRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-004")
}

func TestScenario_REF_005_ScopeUpgradeSingleRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-005")
}

func TestScenario_REF_006_ScopeUpgradeMultipleRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-006")
}

func TestScenario_REF_007_ScopeNarrowDropsOpenidNoIDToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-007")
}

func TestScenario_REF_008_ScopeNarrowKeepsOpenidIssuesIDToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-008")
}

func TestScenario_REF_009_RefreshAccountNotFoundRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-009")
}

func TestScenario_REF_010_RefreshTokenParamRequired(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-010")
}

func TestScenario_REF_011_UnknownRefreshTokenRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-011")
}

func TestScenario_REF_012_RotationEntitiesIncludeBothTokens(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-012")
}

func TestScenario_REF_013_RotationFirstRedemptionMintsNewToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-013")
}

func TestScenario_REF_014_RotationDefaultScopeInheritsOriginal(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-014")
}

func TestScenario_REF_015_RotationNarrowedScopeRetainsOriginal(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-015")
}

func TestScenario_REF_016_RotationReplayRevokesGrantChain(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-016")
}

func TestScenario_REF_017_PredicateTrueRotationEntities(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-017")
}

func TestScenario_REF_018_PredicateTrueFirstRedemption(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-018")
}

func TestScenario_REF_019_PredicateTrueScopeInheritance(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-019")
}

func TestScenario_REF_020_PredicateTrueNarrowedScopeRequest(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-020")
}

func TestScenario_REF_021_PredicateTrueReplayRevokesChain(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-021")
}

func TestScenario_REF_022_PredicateFalseReusesRefreshToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-022")
}
