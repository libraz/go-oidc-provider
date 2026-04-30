package scenarios_test

// Catalog: test/scenarios/catalog/jar.yaml (JAR-NNN)
// Spec:
//   - RFC 9101 — JWT-Secured Authorization Request (JAR)
//   - OpenID Connect Core 1.0 §6
//   - OpenID Connect Discovery 1.0 §3
//   - RFC 8628 §3.1 — Device Authorization Endpoint

import "testing"

func TestScenario_JAR_001_DiscoveryRequestParameterSupported(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-001")
}

func TestScenario_JAR_002_DiscoveryRequireSignedRequestObject(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-002")
}

func TestScenario_JAR_003_RequestObjectOverridesOuterParams(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-003")
}

func TestScenario_JAR_004_NumericClaimsCoercedToString(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-004")
}

func TestScenario_JAR_005_DuplicateScopeArrayRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-005")
}

func TestScenario_JAR_006_ClaimsAsStringPassthrough(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-006")
}

func TestScenario_JAR_007_ClaimsAsObjectReserialised(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-007")
}

func TestScenario_JAR_008_ClockSkewToleranceAccepted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-008")
}

func TestScenario_JAR_009_HS256AcceptedForRegisteredClient(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-009")
}

func TestScenario_JAR_010_ExpiredSecretRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-010")
}

func TestScenario_JAR_011_NestedRequestParameterForbidden(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-011")
}

func TestScenario_JAR_012_NestedRequestUriForbidden(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-012")
}

func TestScenario_JAR_013_ResponseModeFragmentHonoured(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-013")
}

func TestScenario_JAR_014_UnsupportedResponseModeRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-014")
}

func TestScenario_JAR_015_ResponseTypeMismatchRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-015")
}

func TestScenario_JAR_016_StatePreservedOnError(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-016")
}

func TestScenario_JAR_017_ClientIDMismatchRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-017")
}

func TestScenario_JAR_018_MalformedJWTRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-018")
}

func TestScenario_JAR_019_PreregisteredAlgEnforced(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-019")
}

func TestScenario_JAR_020_UnsupportedAlgRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-020")
}

func TestScenario_JAR_021_SignatureVerificationFails(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-021")
}

func TestScenario_JAR_022_RegistrationClaimForbidden(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-022")
}

func TestScenario_JAR_023_UnknownMembersIgnored(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JAR-023")
}
