package scenarios_test

// Catalog: test/scenarios/catalog/external_signing.yaml (ESK-NNN)
// Spec:
//   - RFC 7515 — JSON Web Signature (abstract Sign)
//   - RFC 7517 — JSON Web Key
//   - OIDC Core 1.0 §10, §3.1.3.7 (ID Token validation via JWKS)
//   - NIST SP 800-57 — key lifecycle / HSM
//   - AWS KMS / GCP KMS / Azure Key Vault sign APIs (informational)

import "testing"

func TestScenario_ESK_001_InProcessSignerStillIssuesIDToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ESK-001")
}

func TestScenario_ESK_002_ExternalSignerPublicKeyInJWKS(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ESK-002")
}

func TestScenario_ESK_003_ExternalIDTokenVerifiesViaRemoteJWKS(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ESK-003")
}

func TestScenario_ESK_010_ExternalIDTokenAcceptedAsHint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ESK-010")
}

func TestScenario_ESK_020_SignerInterfaceIsInterchangeable(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ESK-020")
}

func TestScenario_ESK_021_ExternalSignerHonoursContextCancel(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ESK-021")
}

func TestScenario_ESK_022_ExternalKeyLifecycleSyncsToJWKS(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ESK-022")
}

func TestScenario_ESK_023_PrivateKeyMaterialNeverExtracted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ESK-023")
}

func TestScenario_ESK_030_SignerTimeoutMapsToServerError(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ESK-030")
}

func TestScenario_ESK_031_SignerPermissionDenialDoesNotLeak(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ESK-031")
}

func TestScenario_ESK_040_FixturesTogglePerClientSigner(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ESK-040")
}
