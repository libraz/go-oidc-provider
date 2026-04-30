package scenarios_test

// Catalog: test/scenarios/catalog/token_formats_opaque.yaml (TFO-NNN)
// Spec:
//   - RFC 6749 / RFC 6750 — OAuth 2.0 / Bearer
//   - RFC 7009 / RFC 7662 — Revocation / Introspection
//   - RFC 8628 — Device Authorization Grant
//   - OIDC Core 1.0 §3 — AuthorizationCode / IdToken
//   - RFC 7591 / RFC 7592 — Initial / Registration access tokens
//   - OIDC CIBA — Backchannel authentication request
//   - RFC 8705 / RFC 9449 — `x5t#S256` / `jkt` confirmation

import "testing"

func TestScenario_TFO_001_AccessTokenUpsertPayload(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFO-001")
}

func TestScenario_TFO_002_AccessTokenExtraClaimsHook(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFO-002")
}

func TestScenario_TFO_003_AuthorizationCodeUpsertPayload(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFO-003")
}

func TestScenario_TFO_004_DeviceCodeUpsertPayload(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFO-004")
}

func TestScenario_TFO_005_BackchannelAuthRequestUpsertPayload(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFO-005")
}

func TestScenario_TFO_006_RefreshTokenUpsertPayload(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFO-006")
}

func TestScenario_TFO_007_ClientCredentialsUpsertPayload(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFO-007")
}

func TestScenario_TFO_008_ClientCredentialsExtraClaimsHook(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFO-008")
}

func TestScenario_TFO_009_InitialAccessTokenUpsertPayload(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFO-009")
}

func TestScenario_TFO_010_RegistrationAccessTokenUpsertPayload(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFO-010")
}
