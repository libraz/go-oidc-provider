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
//
// DEPRECATED: the TFO catalog enumerates the panva/node-oidc-provider
// adapter.upsert payload contract, which go-oidc-provider v1.0 does
// not adopt (see ADR 0024). The v1.0 opaque access-token surface is
// exercised by the ATO-NNN catalog under
// test/scenarios/catalog/access_token_opaque.yaml; the test functions
// in this file remain as historical placeholders only.

import "testing"

func TestScenario_TFO_001_AccessTokenUpsertPayload(t *testing.T) {
	t.Parallel()
	t.Skip("TFO-001: superseded by ATO scenarios; see catalog/access_token_opaque.yaml and ADR 0024")
}

func TestScenario_TFO_002_AccessTokenExtraClaimsHook(t *testing.T) {
	t.Parallel()
	t.Skip("TFO-002: superseded by ATO scenarios; see catalog/access_token_opaque.yaml and ADR 0024")
}

func TestScenario_TFO_003_AuthorizationCodeUpsertPayload(t *testing.T) {
	t.Parallel()
	t.Skip("TFO-003: superseded by ATO scenarios; see catalog/access_token_opaque.yaml and ADR 0024")
}

func TestScenario_TFO_004_DeviceCodeUpsertPayload(t *testing.T) {
	t.Parallel()
	t.Skip("TFO-004: superseded by ATO scenarios; see catalog/access_token_opaque.yaml and ADR 0024")
}

func TestScenario_TFO_005_BackchannelAuthRequestUpsertPayload(t *testing.T) {
	t.Parallel()
	t.Skip("TFO-005: superseded by ATO scenarios; see catalog/access_token_opaque.yaml and ADR 0024")
}

func TestScenario_TFO_006_RefreshTokenUpsertPayload(t *testing.T) {
	t.Parallel()
	t.Skip("TFO-006: superseded by ATO scenarios; see catalog/access_token_opaque.yaml and ADR 0024")
}

func TestScenario_TFO_007_ClientCredentialsUpsertPayload(t *testing.T) {
	t.Parallel()
	t.Skip("TFO-007: superseded by ATO scenarios; see catalog/access_token_opaque.yaml and ADR 0024")
}

func TestScenario_TFO_008_ClientCredentialsExtraClaimsHook(t *testing.T) {
	t.Parallel()
	t.Skip("TFO-008: superseded by ATO scenarios; see catalog/access_token_opaque.yaml and ADR 0024")
}

func TestScenario_TFO_009_InitialAccessTokenUpsertPayload(t *testing.T) {
	t.Parallel()
	t.Skip("TFO-009: superseded by ATO scenarios; see catalog/access_token_opaque.yaml and ADR 0024")
}

func TestScenario_TFO_010_RegistrationAccessTokenUpsertPayload(t *testing.T) {
	t.Parallel()
	t.Skip("TFO-010: superseded by ATO scenarios; see catalog/access_token_opaque.yaml and ADR 0024")
}
