package scenarios_test

// Catalog: test/scenarios/catalog/external_signing.yaml (ESK-NNN)
// Spec:
//   - RFC 7515 — JSON Web Signature (abstract Sign)
//   - RFC 7517 — JSON Web Key
//   - OIDC Core 1.0 §10, §3.1.3.7 (ID Token validation via JWKS)
//   - NIST SP 800-57 — key lifecycle / HSM
//   - AWS KMS / GCP KMS / Azure Key Vault sign APIs (informational)

import "testing"

// TestScenario_ESK_001_InProcessSignerStillIssuesIDToken is OOS — see catalog out_of_scope_reason.
func TestScenario_ESK_001_InProcessSignerStillIssuesIDToken(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ESK-001 (see catalog out_of_scope_reason)")
}

// TestScenario_ESK_002_ExternalSignerPublicKeyInJWKS is OOS — see catalog out_of_scope_reason.
func TestScenario_ESK_002_ExternalSignerPublicKeyInJWKS(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ESK-002 (see catalog out_of_scope_reason)")
}

// TestScenario_ESK_003_ExternalIDTokenVerifiesViaRemoteJWKS is OOS — see catalog out_of_scope_reason.
func TestScenario_ESK_003_ExternalIDTokenVerifiesViaRemoteJWKS(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ESK-003 (see catalog out_of_scope_reason)")
}

// TestScenario_ESK_010_ExternalIDTokenAcceptedAsHint is OOS — see catalog out_of_scope_reason.
func TestScenario_ESK_010_ExternalIDTokenAcceptedAsHint(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ESK-010 (see catalog out_of_scope_reason)")
}

// TestScenario_ESK_020_SignerInterfaceIsInterchangeable is OOS — see catalog out_of_scope_reason.
func TestScenario_ESK_020_SignerInterfaceIsInterchangeable(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ESK-020 (see catalog out_of_scope_reason)")
}

// TestScenario_ESK_021_ExternalSignerHonoursContextCancel is OOS — see catalog out_of_scope_reason.
func TestScenario_ESK_021_ExternalSignerHonoursContextCancel(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ESK-021 (see catalog out_of_scope_reason)")
}

// TestScenario_ESK_022_ExternalKeyLifecycleSyncsToJWKS is OOS — see catalog out_of_scope_reason.
func TestScenario_ESK_022_ExternalKeyLifecycleSyncsToJWKS(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ESK-022 (see catalog out_of_scope_reason)")
}

// TestScenario_ESK_023_PrivateKeyMaterialNeverExtracted is OOS — see catalog out_of_scope_reason.
func TestScenario_ESK_023_PrivateKeyMaterialNeverExtracted(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ESK-023 (see catalog out_of_scope_reason)")
}

// TestScenario_ESK_030_SignerTimeoutMapsToServerError is OOS — see catalog out_of_scope_reason.
func TestScenario_ESK_030_SignerTimeoutMapsToServerError(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ESK-030 (see catalog out_of_scope_reason)")
}

// TestScenario_ESK_031_SignerPermissionDenialDoesNotLeak is OOS — see catalog out_of_scope_reason.
func TestScenario_ESK_031_SignerPermissionDenialDoesNotLeak(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ESK-031 (see catalog out_of_scope_reason)")
}

// TestScenario_ESK_040_FixturesTogglePerClientSigner is OOS — see catalog out_of_scope_reason.
func TestScenario_ESK_040_FixturesTogglePerClientSigner(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ESK-040 (see catalog out_of_scope_reason)")
}
