package scenarios_test

// Catalog: test/scenarios/catalog/userinfo.yaml (UI-NNN)
// Spec:
//   - OIDC Core 1.0 §5.3, §5.3.1, §5.3.2, §5.3.3, §5.4
//   - RFC 6750 §2, §3 (Bearer)
//   - RFC 6749 §5.2, §10.4
//   - RFC 7235 §2.1
//   - RFC 9449 §7 (DPoP error responses)
//   - OIDC Discovery 1.0 (`userinfo_endpoint`)

import "testing"

func TestScenario_UI_001_JWTUserinfoRequiresEndpointEnabled(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-001")
}

func TestScenario_UI_002_GETReturnsClaimsHonoringRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-002")
}

func TestScenario_UI_003_POSTReturnsSameBody(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-003")
}

func TestScenario_UI_004_RequestContextEntitiesPopulated(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-004")
}

func TestScenario_UI_005_UnknownTokenReturnsInvalidToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-005")
}

func TestScenario_UI_006_NoTokenReturnsInvalidToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-006")
}

func TestScenario_UI_007_MissingOpenIDScopeReturnsInsufficientScope(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-007")
}

func TestScenario_UI_008_ClientGoneReturnsInvalidToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-008")
}

func TestScenario_UI_009_AccountGoneReturnsInvalidToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-009")
}

func TestScenario_UI_010_RequestNarrowsScopeAllowed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-010")
}

func TestScenario_UI_011_RequestExpandsScopeForbidden(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-011")
}

func TestScenario_UI_012_NoBearerEnumeratesBothChallenges(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-012")
}

func TestScenario_UI_013_MultipleBearerCarriersRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-013")
}

func TestScenario_UI_014_AuthorizationHeaderOnePartRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-014")
}

func TestScenario_UI_015_AuthorizationHeaderTooManyPartsRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-015")
}

func TestScenario_UI_016_WrongAuthSchemeRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-016")
}

func TestScenario_UI_017_EmptyTokenViaQueryRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-017")
}

func TestScenario_UI_018_EmptyTokenViaBodyRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-018")
}

func TestScenario_UI_019_EmptyBodyAndNoHeaderRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: UI-019")
}
