package scenarios_test

// Catalog: test/scenarios/catalog/encryption.yaml (ENC-NNN)
// Spec:
//   - RFC 7516 — JSON Web Encryption
//   - RFC 7517 §4.2 — use=sig / use=enc separation
//   - RFC 7518 — JSON Web Algorithms (alg / enc)
//   - RFC 7519 §11 — JWE-nested-JWT
//   - RFC 8037 — CFRG curves
//   - OIDC Core 1.0 §3.1.3.7, §10.1, §10.2, §16.7
//   - OIDC Discovery 1.0 §3 (`*_encryption_alg/enc_values_supported`)
//   - RFC 9101 — JWT-Secured Authorization Request (JAR)
//   - RFC 9126 — Pushed Authorization Requests (PAR)
//   - RFC 9701 — JWT Response for OAuth Token Introspection
//   - FAPI 2.0 Message Signing §5.5 (JARM)

import "testing"

// TestScenario_ENC_001_SymmetricAlgRequiresClientSecret is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_001_SymmetricAlgRequiresClientSecret(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-001 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_002_ExpiredSecretBlocksSymmetricIDToken is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_002_ExpiredSecretBlocksSymmetricIDToken(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-002 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_010_DiscoveryAdvertisesEncryptionMetadata pending — bind in T1-E follow-up.
func TestScenario_ENC_010_DiscoveryAdvertisesEncryptionMetadata(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-010")
}

// TestScenario_ENC_020_NestedJWEIsFivePartCompact pending — bind in T1-E follow-up.
func TestScenario_ENC_020_NestedJWEIsFivePartCompact(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-020")
}

// TestScenario_ENC_021_EncryptedIDTokenHeaderCarriesIssAud is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_021_EncryptedIDTokenHeaderCarriesIssAud(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-021 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_022_EncryptedUserInfoResponseShape is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_022_EncryptedUserInfoResponseShape(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-022 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_023_ExpiredSecretBlocksHS256UserInfo is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_023_ExpiredSecretBlocksHS256UserInfo(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-023 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_024_ExpiredSecretBlocksDirUserInfo is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_024_ExpiredSecretBlocksDirUserInfo(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-024 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_030_UnsupportedAlgRejectsRequestObject pending — bind in T1-E follow-up.
func TestScenario_ENC_030_UnsupportedAlgRejectsRequestObject(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-030")
}

// TestScenario_ENC_031_UnsupportedEncRejectsRequestObject pending — bind in T1-E follow-up.
func TestScenario_ENC_031_UnsupportedEncRejectsRequestObject(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-031")
}

// TestScenario_ENC_032_DefaultJWEInventoryFromKeystore pending — bind in T1-E follow-up.
func TestScenario_ENC_032_DefaultJWEInventoryFromKeystore(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-032")
}

// TestScenario_ENC_040_PARAcceptsEncryptedRequestObject pending — bind in T1-E follow-up.
func TestScenario_ENC_040_PARAcceptsEncryptedRequestObject(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-040")
}

// TestScenario_ENC_041_PARRespectsPerClientSigningAlg is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_041_PARRespectsPerClientSigningAlg(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-041 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_050_ECDHESRequiresClientECKey is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_050_ECDHESRequiresClientECKey(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-050 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_060_AcceptsA128KWRequestObject is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_060_AcceptsA128KWRequestObject(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-060 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_061_ExpiredSecretBlocksSymmetricDecrypt is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_061_ExpiredSecretBlocksSymmetricDecrypt(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-061 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_062_SymmetricIDTokenHeaderShape is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_062_SymmetricIDTokenHeaderShape(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-062 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_070_AcceptsDirRequestObject is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_070_AcceptsDirRequestObject(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-070 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_071_ExpiredSecretBlocksDirDecrypt is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_071_ExpiredSecretBlocksDirDecrypt(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-071 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_072_DirIDTokenHeaderShape is OOS — see catalog out_of_scope_reason.
func TestScenario_ENC_072_DirIDTokenHeaderShape(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: ENC-072 (see catalog out_of_scope_reason)")
}

// TestScenario_ENC_100_AuthorizationCodeIDTokenJWE pending — bind in T1-E follow-up.
func TestScenario_ENC_100_AuthorizationCodeIDTokenJWE(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-100")
}

// TestScenario_ENC_101_RefreshRotatedIDTokenJWE pending — bind in T1-E follow-up.
func TestScenario_ENC_101_RefreshRotatedIDTokenJWE(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-101")
}

// TestScenario_ENC_110_UserInfoJWEOnAcceptJWT pending — bind in T1-E follow-up.
func TestScenario_ENC_110_UserInfoJWEOnAcceptJWT(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-110")
}

// TestScenario_ENC_111_UserInfoJSONWhenAcceptOmitsJWT pending — bind in T1-E follow-up.
func TestScenario_ENC_111_UserInfoJSONWhenAcceptOmitsJWT(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-111")
}

// TestScenario_ENC_120_JARMSuccessJWE pending — bind in T1-E follow-up.
func TestScenario_ENC_120_JARMSuccessJWE(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-120")
}

// TestScenario_ENC_121_JARMErrorFallsBackToSignedOnly pending — bind in T1-E follow-up.
func TestScenario_ENC_121_JARMErrorFallsBackToSignedOnly(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-121")
}

// TestScenario_ENC_130_IntrospectionJWE pending — bind in T1-E follow-up.
func TestScenario_ENC_130_IntrospectionJWE(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-130")
}

// TestScenario_ENC_140_KidDisjointSigEncSeparation pending — bind in T1-E follow-up.
func TestScenario_ENC_140_KidDisjointSigEncSeparation(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-140")
}

// TestScenario_ENC_141_FailClosedOnEncryptionFailure pending — bind in T1-E follow-up.
func TestScenario_ENC_141_FailClosedOnEncryptionFailure(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-141")
}
