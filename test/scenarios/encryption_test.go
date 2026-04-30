package scenarios_test

// Catalog: test/scenarios/catalog/encryption.yaml (ENC-NNN)
// Spec:
//   - RFC 7516 — JSON Web Encryption
//   - RFC 7518 — JSON Web Algorithms (alg / enc)
//   - RFC 7519 §11 — JWE-nested-JWT
//   - RFC 8037 — CFRG curves
//   - OIDC Core 1.0 §3.1.3.7, §10.1, §16.7
//   - OIDC Discovery 1.0 §3 (`*_encryption_alg/enc_values_supported`)
//   - RFC 9101 — JWT-Secured Authorization Request (JAR)
//   - RFC 9126 — Pushed Authorization Requests (PAR)

import "testing"

func TestScenario_ENC_001_SymmetricAlgRequiresClientSecret(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-001")
}

func TestScenario_ENC_002_ExpiredSecretBlocksSymmetricIDToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-002")
}

func TestScenario_ENC_010_DiscoveryAdvertisesEncryptionMetadata(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-010")
}

func TestScenario_ENC_020_NestedJWEIsFivePartCompact(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-020")
}

func TestScenario_ENC_021_EncryptedIDTokenHeaderCarriesIssAud(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-021")
}

func TestScenario_ENC_022_EncryptedUserInfoResponseShape(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-022")
}

func TestScenario_ENC_023_ExpiredSecretBlocksHS256UserInfo(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-023")
}

func TestScenario_ENC_024_ExpiredSecretBlocksDirUserInfo(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-024")
}

func TestScenario_ENC_030_UnsupportedAlgRejectsRequestObject(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-030")
}

func TestScenario_ENC_031_UnsupportedEncRejectsRequestObject(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-031")
}

func TestScenario_ENC_032_DefaultJWEInventoryFromKeystore(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-032")
}

func TestScenario_ENC_040_PARAcceptsEncryptedRequestObject(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-040")
}

func TestScenario_ENC_041_PARRespectsPerClientSigningAlg(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-041")
}

func TestScenario_ENC_050_ECDHESRequiresClientECKey(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-050")
}

func TestScenario_ENC_060_AcceptsA128KWRequestObject(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-060")
}

func TestScenario_ENC_061_ExpiredSecretBlocksSymmetricDecrypt(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-061")
}

func TestScenario_ENC_062_SymmetricIDTokenHeaderShape(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-062")
}

func TestScenario_ENC_070_AcceptsDirRequestObject(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-070")
}

func TestScenario_ENC_071_ExpiredSecretBlocksDirDecrypt(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-071")
}

func TestScenario_ENC_072_DirIDTokenHeaderShape(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-072")
}
