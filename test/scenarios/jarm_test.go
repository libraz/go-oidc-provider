package scenarios_test

// Catalog: test/scenarios/catalog/jarm.yaml (JARM-NNN)
// Spec:
//   - OAuth 2.0 JWT Secured Authorization Response Mode (JARM)
//   - RFC 7515 — JSON Web Signature
//   - RFC 7516 — JSON Web Encryption
//   - RFC 8414 — OAuth 2.0 Authorization Server Metadata
//   - RFC 9101 — JWT-Secured Authorization Request (JAR)
//   - OpenID Connect Core 1.0 §3.1.2, §3.3
//   - RFC 9207 — Authorization Server Issuer Identification

import "testing"

func TestScenario_JARM_001_DiscoverySurfaceAdvertised(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-001")
}

func TestScenario_JARM_010_JwtModeFragmentForImplicitHybrid(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-010")
}

func TestScenario_JARM_011_JwtModeQueryForCode(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-011")
}

func TestScenario_JARM_012_JwtModeQueryForNone(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-012")
}

func TestScenario_JARM_020_AudEqualsClientID(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-020")
}

func TestScenario_JARM_021_ExpClaimIsNumber(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-021")
}

func TestScenario_JARM_022_IssEqualsIssuer(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-022")
}

func TestScenario_JARM_023_StateRoundTripped(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-023")
}

func TestScenario_JARM_030_ExpiredSecretSurfacesInvalidClient(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-030")
}

func TestScenario_JARM_040_QueryJwtUnencryptedForbiddenForHybrid(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-040")
}

func TestScenario_JARM_041_QueryJwtAllowedWithEncryption(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-041")
}

func TestScenario_JARM_042_QueryJwtSuccessForCode(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-042")
}

func TestScenario_JARM_043_QueryJwtSuccessForNone(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-043")
}

func TestScenario_JARM_044_QueryJwtExpiredSecretBareError(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-044")
}

func TestScenario_JARM_050_QueryJwtErrorRedirect(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-050")
}

func TestScenario_JARM_051_FragmentJwtErrorRedirect(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-051")
}

func TestScenario_JARM_052_FormPostJwtErrorRendered(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-052")
}

func TestScenario_JARM_053_WebMessageJwtErrorRendered(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-053")
}

func TestScenario_JARM_054_ExpiredSecretAllTransports(t *testing.T) {
	t.Parallel()
	t.Skip("pending: JARM-054")
}
