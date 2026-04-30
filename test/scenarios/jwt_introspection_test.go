package scenarios_test

// Catalog: test/scenarios/catalog/jwt_introspection.yaml (JINT-NNN)
// Spec:
//   - RFC 9701 — JWT Response for OAuth 2.0 Token Introspection
//   - RFC 7662 — OAuth 2.0 Token Introspection (prerequisite)
//   - RFC 7515 / 7516 / 7518 — JWS / JWE / JWA
//   - RFC 8414 §2 — `introspection_signing_alg_values_supported`
//   - OIDC Core 1.0 §10

import "testing"

func TestScenario_JINT_001_DiscoveryAdvertisesSigningAlgs(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JINT-001")
}

func TestScenario_JINT_002_FeatureRequiresIntrospection(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JINT-002")
}

func TestScenario_JINT_003_DefaultJSONWhenAcceptOmitted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JINT-003")
}

func TestScenario_JINT_004_JWTBodyForMatchingAcceptHeader(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JINT-004")
}

func TestScenario_JINT_005_JWTEnvelopeClaimsPresent(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JINT-005")
}

func TestScenario_JINT_006_JWTHeaderTypeIsTokenIntrospection(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JINT-006")
}

func TestScenario_JINT_007_JWTIatProgressesWithClock(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JINT-007")
}

func TestScenario_JINT_008_ActiveFalseShapeForJWTResponse(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JINT-008")
}

func TestScenario_JINT_009_HMACAlgRejectedWhenSecretExpired(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JINT-009")
}

func TestScenario_JINT_010_EncryptedClientRequiresJWTAccept(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JINT-010")
}

func TestScenario_JINT_011_EncryptedJWTResponseEnvelope(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JINT-011")
}
