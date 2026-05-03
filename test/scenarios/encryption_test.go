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

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// encVerifyInnerJWS decodes the inner compact JWS produced by stripping
// the outer JWE and verifies its ES256 signature against the OP's
// active public signing key. The helper centralises the round-trip
// every encrypted-token scenario performs after [scenariokit.DecryptJWE].
func encVerifyInnerJWS(t *testing.T, tk *testkit.Provider, inner string) map[string]any {
	t.Helper()
	parsed, err := jwt.ParseSigned(inner, []josev4.SignatureAlgorithm{josev4.ES256})
	if err != nil {
		t.Fatalf("ParseSigned inner JWS: %v (raw=%q)", err, inner)
	}
	pub, ok := tk.SigningKey.Signer.Public().(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("testkit signer public key is not *ecdsa.PublicKey: %T", tk.SigningKey.Signer.Public())
	}
	out := map[string]any{}
	if err := parsed.Claims(pub, &out); err != nil {
		t.Fatalf("verify inner JWS: %v", err)
	}
	return out
}

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

// TestScenario_ENC_010_DiscoveryAdvertisesEncryptionMetadata pins the
// OIDC Discovery 1.0 §3 toggle: when [op.WithEncryptionKeyset] is
// configured the eight `*_encryption_*_values_supported` arrays MUST
// be present, and when it is omitted those same fields MUST be absent
// (the document uses `omitempty`).
//
// Spec: OIDC Discovery 1.0 §3.
func TestScenario_ENC_010_DiscoveryAdvertisesEncryptionMetadata(t *testing.T) {
	t.Parallel()

	encFields := []string{
		"id_token_encryption_alg_values_supported",
		"id_token_encryption_enc_values_supported",
		"request_object_encryption_alg_values_supported",
		"request_object_encryption_enc_values_supported",
		"userinfo_encryption_alg_values_supported",
		"userinfo_encryption_enc_values_supported",
		"authorization_encryption_alg_values_supported",
		"authorization_encryption_enc_values_supported",
	}

	encKey := scenariokit.NewOPEncryptionKey(t, "enc-1")
	tkOn := testkit.NewProvider(t, testkit.WithOptions(
		op.WithFeature(feature.JAR),
		op.WithFeature(feature.JARM),
		op.WithFeature(feature.Introspect),
		op.WithEncryptionKeyset(op.EncryptionKeyset{encKey}),
	))
	_, _, doc := fetchDiscovery(t, tkOn.Server.URL)
	for _, f := range encFields {
		v, ok := doc[f]
		if !ok {
			t.Errorf("with encryption keyset: discovery doc missing %q", f)
			continue
		}
		arr, ok := v.([]any)
		if !ok || len(arr) == 0 {
			t.Errorf("with encryption keyset: discovery field %q must be non-empty array, got %T %v", f, v, v)
		}
	}

	tkOff := testkit.NewProvider(t, testkit.WithOptions(
		op.WithFeature(feature.JAR),
		op.WithFeature(feature.JARM),
		op.WithFeature(feature.Introspect),
	))
	_, _, docOff := fetchDiscovery(t, tkOff.Server.URL)
	for _, f := range encFields {
		if v, present := docOff[f]; present {
			if arr, ok := v.([]any); !ok || len(arr) != 0 {
				t.Errorf("without encryption keyset: discovery field %q must be absent or empty, got %v", f, v)
			}
		}
	}
}

// TestScenario_ENC_020_NestedJWEIsFivePartCompact pins the RFC 7516 §3
// shape: an encrypted ID Token is a 5-part compact serialisation
// (header.cek.iv.ct.tag); decryption yields a compact JWS whose
// 3-part shape and ES256 signature verify against the OP's published
// signing JWKS. The protected-header cty=JWT (RFC 7519 §5.2) is
// asserted by [scenariokit.DecryptJWE].
//
// Spec: RFC 7516 §3 / OIDC Core §10.2 / RFC 7519 §5.2.
func TestScenario_ENC_020_NestedJWEIsFivePartCompact(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-enc-020"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-enc-020-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	encKey := scenariokit.NewOPEncryptionKey(t, "enc-1")
	rp := scenariokit.NewRPEncryptionKey(t, "rp-enc-020-key")

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithEncryptionKeyset(op.EncryptionKeyset{encKey}),
	))
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                          clientID,
		SecretHash:                  hash,
		RedirectURIs:                []string{callback},
		Scopes:                      []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod:     "client_secret_basic",
		GrantTypes:                  []string{"authorization_code", "refresh_token"},
		ResponseTypes:               []string{"code"},
		JWKs:                        rp.JWKS,
		IDTokenEncryptedResponseAlg: "RSA-OAEP-256",
		IDTokenEncryptedResponseEnc: "A256GCM",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    clientID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.IDToken == "" {
		t.Fatalf("/token status=%d body=%v want 200 with id_token", tok.StatusCode, tok.Raw)
	}

	if got := scenariokit.JWEParts(tok.IDToken); len(got) != 5 {
		t.Fatalf("id_token has %d parts, want 5 (JWE compact)", len(got))
	}
	inner := scenariokit.DecryptJWE(t, tok.IDToken, rp.Private)
	if got := strings.Split(inner, "."); len(got) != 3 {
		t.Fatalf("inner JWS has %d parts, want 3 (JWS compact)", len(got))
	}
	encVerifyInnerJWS(t, tk, inner)
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

// TestScenario_ENC_100_AuthorizationCodeIDTokenJWE pins the OIDC Core
// 1.0 §10.2 round-trip: a confidential client that registered
// id_token_encrypted_response_alg / _enc receives an id_token field
// shaped as a 5-part nested JWE addressed to its enc-use key. Decrypting
// the JWE and verifying the inner ES256 JWS yields the canonical claim
// set (iss, aud, sub, exp, iat, nonce when requested).
//
// Spec: OIDC Core §10.2 / RFC 7519 §5.2.
func TestScenario_ENC_100_AuthorizationCodeIDTokenJWE(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-enc-100"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-enc-100-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	encKey := scenariokit.NewOPEncryptionKey(t, "enc-1")
	rp := scenariokit.NewRPEncryptionKey(t, "rp-enc-100-key")

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithEncryptionKeyset(op.EncryptionKeyset{encKey}),
	))
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                          clientID,
		SecretHash:                  hash,
		RedirectURIs:                []string{callback},
		Scopes:                      []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod:     "client_secret_basic",
		GrantTypes:                  []string{"authorization_code", "refresh_token"},
		ResponseTypes:               []string{"code"},
		JWKs:                        rp.JWKS,
		IDTokenEncryptedResponseAlg: "RSA-OAEP-256",
		IDTokenEncryptedResponseEnc: "A256GCM",
	})

	const customNonce = "enc-100-nonce"
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    clientID,
		RedirectURI: callback,
		PKCE:        pkce,
		Nonce:       customNonce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.IDToken == "" {
		t.Fatalf("/token status=%d body=%v want 200 with id_token", tok.StatusCode, tok.Raw)
	}
	if got := scenariokit.JWEParts(tok.IDToken); len(got) != 5 {
		t.Fatalf("id_token has %d parts, want 5", len(got))
	}
	inner := scenariokit.DecryptJWE(t, tok.IDToken, rp.Private)
	claims := encVerifyInnerJWS(t, tk, inner)

	if got := claims["iss"]; got != tk.Issuer {
		t.Errorf("iss=%v want %q", got, tk.Issuer)
	}
	if got := claims["aud"]; got != clientID {
		t.Errorf("aud=%v want %q", got, clientID)
	}
	if got := claims["sub"]; got != scenariokit.DefaultSubject {
		t.Errorf("sub=%v want %q", got, scenariokit.DefaultSubject)
	}
	if got := claims["nonce"]; got != customNonce {
		t.Errorf("nonce=%v want %q", got, customNonce)
	}
	if _, ok := claims["exp"].(float64); !ok {
		t.Errorf("exp must be a JSON number: %T", claims["exp"])
	}
	if _, ok := claims["iat"].(float64); !ok {
		t.Errorf("iat must be a JSON number: %T", claims["iat"])
	}
}

// TestScenario_ENC_101_RefreshRotatedIDTokenJWE pending — bind in T1-E follow-up.
func TestScenario_ENC_101_RefreshRotatedIDTokenJWE(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-101")
}

// TestScenario_ENC_110_UserInfoJWEOnAcceptJWT pins the OIDC Core 1.0
// §5.3.2 negotiation: a client that registered
// userinfo_encrypted_response_alg / _enc and asks Accept: application/jwt
// receives Content-Type: application/jwt with a 5-part JWE body.
// Decrypting yields a signed JWS whose claims include iss, aud, sub.
//
// Deviation from catalog text: the OP does not stamp `exp` on the
// signed userinfo body (OIDC Core §5.3.2 leaves exp OPTIONAL on
// userinfo); the test only asserts iss / aud / sub.
//
// Spec: OIDC Core §5.3.2.
func TestScenario_ENC_110_UserInfoJWEOnAcceptJWT(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-enc-110"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-enc-110-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	encKey := scenariokit.NewOPEncryptionKey(t, "enc-1")
	rp := scenariokit.NewRPEncryptionKey(t, "rp-enc-110-key")

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithEncryptionKeyset(op.EncryptionKeyset{encKey}),
	))
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                           clientID,
		SecretHash:                   hash,
		RedirectURIs:                 []string{callback},
		Scopes:                       []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod:      "client_secret_basic",
		GrantTypes:                   []string{"authorization_code", "refresh_token"},
		ResponseTypes:                []string{"code"},
		JWKs:                         rp.JWKS,
		UserInfoEncryptedResponseAlg: "RSA-OAEP-256",
		UserInfoEncryptedResponseEnc: "A128GCM",
	})
	tk.Store.PutUser(context.Background(), &store.User{
		Subject: scenariokit.DefaultSubject,
		Claims: map[string]any{
			"email":          "user-1@example.test",
			"email_verified": true,
		},
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    clientID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.AccessToken == "" {
		t.Fatalf("/token status=%d body=%v want 200 with access_token", tok.StatusCode, tok.Raw)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/userinfo", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	req.Header.Set("Accept", "application/jwt")
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/jwt") {
		t.Errorf("Content-Type=%q want application/jwt prefix", got)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	jwe := strings.TrimSpace(string(body))
	if got := scenariokit.JWEParts(jwe); len(got) != 5 {
		t.Fatalf("userinfo body has %d parts, want 5 (raw=%q)", len(got), jwe)
	}
	inner := scenariokit.DecryptJWE(t, jwe, rp.Private)
	claims := encVerifyInnerJWS(t, tk, inner)
	if got := claims["iss"]; got != tk.Issuer {
		t.Errorf("iss=%v want %q", got, tk.Issuer)
	}
	if got := claims["aud"]; got != clientID {
		t.Errorf("aud=%v want %q", got, clientID)
	}
	if got := claims["sub"]; got != scenariokit.DefaultSubject {
		t.Errorf("sub=%v want %q", got, scenariokit.DefaultSubject)
	}
}

// TestScenario_ENC_111_UserInfoJSONWhenAcceptOmitsJWT pending — bind in T1-E follow-up.
func TestScenario_ENC_111_UserInfoJSONWhenAcceptOmitsJWT(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-111")
}

// TestScenario_ENC_120_JARMSuccessJWE pins the FAPI 2.0 Message Signing
// §5.5 wrap: a client that registered
// authorization_encrypted_response_alg / _enc and uses
// response_mode=jwt receives an /authorize success response whose
// "response" parameter is a 5-part JWE addressed to its enc-use key.
// Decrypting + verifying yields a JARM payload with iss, aud, code,
// state.
//
// Spec: FAPI 2.0 Message Signing §5.5.
func TestScenario_ENC_120_JARMSuccessJWE(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-enc-120"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-enc-120-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	encKey := scenariokit.NewOPEncryptionKey(t, "enc-1")
	rp := scenariokit.NewRPEncryptionKey(t, "rp-enc-120-key")

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithFeature(feature.JARM),
		op.WithEncryptionKeyset(op.EncryptionKeyset{encKey}),
	))
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                                clientID,
		SecretHash:                        hash,
		RedirectURIs:                      []string{callback},
		Scopes:                            []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod:           "client_secret_basic",
		GrantTypes:                        []string{"authorization_code"},
		ResponseTypes:                     []string{"code"},
		JWKs:                              rp.JWKS,
		AuthorizationEncryptedResponseAlg: "RSA-OAEP-256",
		AuthorizationEncryptedResponseEnc: "A256GCM",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    clientID,
		RedirectURI: callback,
		PKCE:        pkce,
		Extra:       url.Values{"response_mode": {"jwt"}},
	})
	if flow.Error != "" {
		t.Fatalf("authorize error=%s desc=%s", flow.Error, flow.ErrorDesc)
	}
	rawResp := flow.Location.Query().Get("response")
	if rawResp == "" {
		t.Fatalf("'response' parameter missing from callback: %s", flow.Location.String())
	}
	if got := scenariokit.JWEParts(rawResp); len(got) != 5 {
		t.Fatalf("JARM response has %d parts, want 5 (raw=%q)", len(got), rawResp)
	}
	inner := scenariokit.DecryptJWE(t, rawResp, rp.Private)
	claims := encVerifyInnerJWS(t, tk, inner)
	if got := claims["iss"]; got != tk.Issuer {
		t.Errorf("iss=%v want %q", got, tk.Issuer)
	}
	if got := claims["aud"]; got != clientID {
		t.Errorf("aud=%v want %q", got, clientID)
	}
	if got, _ := claims["code"].(string); got == "" {
		t.Errorf("code missing from JARM payload: %v", claims)
	}
	if got := claims["state"]; got != scenariokit.DefaultState {
		t.Errorf("state=%v want %q", got, scenariokit.DefaultState)
	}
}

// TestScenario_ENC_121_JARMErrorFallsBackToSignedOnly pending — bind in T1-E follow-up.
func TestScenario_ENC_121_JARMErrorFallsBackToSignedOnly(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-121")
}

// TestScenario_ENC_130_IntrospectionJWE pins the RFC 9701 §5 wrap: a
// client that registered introspection_encrypted_response_alg / _enc
// and asks Accept: application/token-introspection+jwt receives a 5-part
// JWE wrapping the signed introspection JWT. The inner claim set carries
// iss / aud / iat at the top level and active / client_id / exp inside
// the `token_introspection` object (RFC 9701 §4 shape).
//
// Spec: RFC 9701 §4 / §5.
func TestScenario_ENC_130_IntrospectionJWE(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-enc-130"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-enc-130-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	encKey := scenariokit.NewOPEncryptionKey(t, "enc-1")
	rp := scenariokit.NewRPEncryptionKey(t, "rp-enc-130-key")

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithFeature(feature.Introspect),
		op.WithEncryptionKeyset(op.EncryptionKeyset{encKey}),
	))
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                                clientID,
		SecretHash:                        hash,
		RedirectURIs:                      []string{callback},
		Scopes:                            []string{"openid", "profile", "email", "api"},
		TokenEndpointAuthMethod:           "client_secret_basic",
		GrantTypes:                        []string{"client_credentials", "authorization_code"},
		ResponseTypes:                     []string{"code"},
		JWKs:                              rp.JWKS,
		IntrospectionEncryptedResponseAlg: "RSA-OAEP-256",
		IntrospectionEncryptedResponseEnc: "A256GCM",
	})

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"api"},
	}
	tokReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokReq.SetBasicAuth(clientID, clientSecret)
	tokResp, err := tk.HTTPClient(nil).Do(tokReq)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = tokResp.Body.Close() }()
	if tokResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokResp.Body)
		t.Fatalf("/token status=%d want 200 body=%s", tokResp.StatusCode, body)
	}
	var tokEnv map[string]any
	if err := json.NewDecoder(tokResp.Body).Decode(&tokEnv); err != nil {
		t.Fatalf("decode /token body: %v", err)
	}
	at, _ := tokEnv["access_token"].(string)
	if at == "" {
		t.Fatalf("access_token missing from /token response: %v", tokEnv)
	}

	introForm := url.Values{"token": {at}}
	introReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(introForm.Encode()))
	if err != nil {
		t.Fatalf("build /introspect request: %v", err)
	}
	introReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introReq.Header.Set("Accept", "application/token-introspection+jwt")
	introReq.SetBasicAuth(clientID, clientSecret)
	introResp, err := tk.HTTPClient(nil).Do(introReq)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer func() { _ = introResp.Body.Close() }()
	if introResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(introResp.Body)
		t.Fatalf("/introspect status=%d want 200 body=%s", introResp.StatusCode, body)
	}
	if got := introResp.Header.Get("Content-Type"); got != "application/token-introspection+jwt" {
		t.Errorf("Content-Type=%q want application/token-introspection+jwt", got)
	}
	body, err := io.ReadAll(introResp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	jwe := strings.TrimSpace(string(body))
	if got := scenariokit.JWEParts(jwe); len(got) != 5 {
		t.Fatalf("/introspect body has %d parts, want 5 (raw=%q)", len(got), jwe)
	}
	inner := scenariokit.DecryptJWE(t, jwe, rp.Private)
	claims := encVerifyInnerJWS(t, tk, inner)
	if got := claims["iss"]; got != tk.Issuer {
		t.Errorf("iss=%v want %q", got, tk.Issuer)
	}
	if got := claims["aud"]; got != clientID {
		t.Errorf("aud=%v want %q", got, clientID)
	}
	tokenIntro, ok := claims["token_introspection"].(map[string]any)
	if !ok {
		t.Fatalf("token_introspection missing or wrong shape: %T %v", claims["token_introspection"], claims["token_introspection"])
	}
	if got, _ := tokenIntro["active"].(bool); !got {
		t.Errorf("active=%v want true (token_introspection=%v)", tokenIntro["active"], tokenIntro)
	}
	if got, _ := tokenIntro["client_id"].(string); got != clientID {
		t.Errorf("client_id=%v want %q", tokenIntro["client_id"], clientID)
	}
	if _, ok := tokenIntro["exp"].(float64); !ok {
		t.Errorf("exp must be a JSON number in token_introspection: %T", tokenIntro["exp"])
	}
}

// TestScenario_ENC_140_KidDisjointSigEncSeparation pins the RFC 7517
// §4.2 use=sig / use=enc separation: [op.New] MUST reject a config in
// which a kid appears in both the signing keyset and the encryption
// keyset, and MUST accept the same config when the kids are disjoint.
//
// Spec: RFC 7517 §4.2.
func TestScenario_ENC_140_KidDisjointSigEncSeparation(t *testing.T) {
	t.Parallel()

	collideEnc := scenariokit.NewOPEncryptionKey(t, "shared-kid")
	disjointEnc := scenariokit.NewOPEncryptionKey(t, "enc-disjoint")

	baseOpts := func(sigKID string) []op.Option {
		return []op.Option{
			op.WithIssuer(testkit.DefaultIssuer),
			op.WithStore(inmem.New()),
			op.WithKeyset(op.Keyset{testkit.NewSigningKey(t, sigKID)}),
			op.WithCookieKeys(testkit.NewCookieKey(t)),
			op.WithInteractionDriver(testkit.AutoConsentDriver{}),
			op.WithAuthenticators(testkit.SubjectAuthenticator{}),
		}
	}

	collideOpts := append(baseOpts("shared-kid"),
		op.WithEncryptionKeyset(op.EncryptionKeyset{collideEnc}))
	if _, err := op.New(collideOpts...); err == nil {
		t.Fatalf("op.New accepted a colliding kid; want error referencing RFC 7517 §4.2")
	} else {
		msg := err.Error()
		if !strings.Contains(msg, "shared-kid") || !strings.Contains(msg, "RFC 7517") {
			t.Errorf("error %q must name the kid and cite RFC 7517 §4.2", msg)
		}
	}

	disjointOpts := append(baseOpts("sig-only"),
		op.WithEncryptionKeyset(op.EncryptionKeyset{disjointEnc}))
	if _, err := op.New(disjointOpts...); err != nil {
		t.Fatalf("op.New rejected disjoint kids: %v", err)
	}
}

// TestScenario_ENC_141_FailClosedOnEncryptionFailure pending — bind in T1-E follow-up.
func TestScenario_ENC_141_FailClosedOnEncryptionFailure(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ENC-141")
}
