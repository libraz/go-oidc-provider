package scenarios_test

// Catalog: test/scenarios/catalog/token_formats_jwt.yaml (TFJ-NNN)
// Spec:
//   - RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens
//   - RFC 7515 / 7516 / 7517 / 7518 / 7519 — JOSE
//   - RFC 8725 — JWT Best Current Practices
//   - OIDC Core 1.0 §10
//   - RFC 8705 — `cnf.x5t#S256`
//   - RFC 9449 — `cnf.jkt`

import "testing"

func TestScenario_TFJ_001_ResourceServerSignAlgPinned(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-001")
}

func TestScenario_TFJ_002_DefaultsWhenJWTBlockOmitted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-002")
}

func TestScenario_TFJ_003_DefaultsWhenJWTBlockEmpty(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-003")
}

func TestScenario_TFJ_004_HMACSignWithRawSecret(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-004")
}

func TestScenario_TFJ_005_HMACSignWithCryptoKey(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-005")
}

func TestScenario_TFJ_006_HMACSignWithKeyObject(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-006")
}

func TestScenario_TFJ_007_SignKidMustBeString(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-007")
}

func TestScenario_TFJ_008_EncryptKidMustBeString(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-008")
}

func TestScenario_TFJ_009_HMACSignEmitsConfiguredKid(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-009")
}

func TestScenario_TFJ_010_PureEncryptedJWTEnvelope(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-010")
}

func TestScenario_TFJ_011_PureEncryptedJWTWithKeyObject(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-011")
}

func TestScenario_TFJ_012_PureEncryptedJWTWithCryptoKey(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-012")
}

func TestScenario_TFJ_013_PureEncryptedJWTEmitsConfiguredKid(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-013")
}

func TestScenario_TFJ_014_NestedJWTExplicitSignAndEncrypt(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-014")
}

func TestScenario_TFJ_015_NestedJWTEmitsConfiguredKid(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-015")
}

func TestScenario_TFJ_016_NestedJWTImplicitSignAlg(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-016")
}

func TestScenario_TFJ_017_AlgNoneRejectedAtSave(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-017")
}

func TestScenario_TFJ_018_HMACMissingKeyRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-018")
}

func TestScenario_TFJ_019_HMACWithAsymmetricPublicKeyRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-019")
}

func TestScenario_TFJ_020_HMACWithAsymmetricPrivateKeyRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-020")
}

func TestScenario_TFJ_021_AsymmetricSignNoMatchingKeystoreKey(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-021")
}

func TestScenario_TFJ_022_EncryptKeyMustNotBePrivate(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-022")
}

func TestScenario_TFJ_023_AsymmetricEncryptRequiresSign(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-023")
}

func TestScenario_TFJ_024_EncryptMissingAlgRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-024")
}

func TestScenario_TFJ_025_EncryptMissingEncRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-025")
}

func TestScenario_TFJ_026_EncryptMissingKeyRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-026")
}

func TestScenario_TFJ_027_JWTAccessTokenNotPersisted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-027")
}

func TestScenario_TFJ_028_AccessTokenJWTPayloadShape(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-028")
}

func TestScenario_TFJ_029_PairwiseAccessTokenJWTPayloadShape(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-029")
}

func TestScenario_TFJ_030_ClientCredentialsJWTPayloadShape(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-030")
}

func TestScenario_TFJ_031_AccessTokenIssuedAuditEmits(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-031")
}

func TestScenario_TFJ_032_ClientCredentialsIssuedAuditEmits(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-032")
}

func TestScenario_TFJ_033_JWTCustomizerHookRewritesEnvelope(t *testing.T) {
	t.Parallel()
	t.Skip("pending: TFJ-033")
}
