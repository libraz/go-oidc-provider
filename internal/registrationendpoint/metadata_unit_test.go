//nolint:testpackage // exercises unexported validatePolicy
package registrationendpoint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	internaljose "github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
)

func TestValidatePolicy_RejectsJWKSAndJWKSURI(t *testing.T) {
	t.Parallel()

	_, err := validatePolicy(ClientMetadata{
		RedirectURIs: []string{"https://rp.test.invalid/cb"},
		JWKs:         []byte(`{"keys":[]}`),
		JWKsURI:      "https://rp.test.invalid/jwks.json",
	}, []string{"authorization_code"}, []string{"code"}, nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

func TestValidatePolicy_RejectsHTTPClientURI(t *testing.T) {
	t.Parallel()

	_, err := validatePolicy(ClientMetadata{
		RedirectURIs: []string{"https://rp.test.invalid/cb"},
		ClientURI:    "http://rp.test.invalid",
	}, []string{"authorization_code"}, []string{"code"}, nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

func TestValidatePolicy_PrivateKeyJWTRequiresJWKS(t *testing.T) {
	t.Parallel()

	//nolint:gosec // G101 false positive: private_key_jwt is an auth-method label.
	_, err := validatePolicy(ClientMetadata{
		RedirectURIs:            []string{"https://rp.test.invalid/cb"},
		TokenEndpointAuthMethod: "private_key_jwt",
	}, []string{"authorization_code"}, []string{"code"}, nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	assertInvalidClientMetadata(t, err)
}

func TestValidatePolicy_PrivateKeyJWTRejectsBadInlineJWKS(t *testing.T) {
	t.Parallel()

	weakRSA, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // deliberately weak M-13 fixture.
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	cases := []struct {
		name string
		jwks []byte
	}{
		{name: "malformed", jwks: []byte(`{"keys":[`)},
		{name: "empty", jwks: []byte(`{"keys":[]}`)},
		{name: "weak_rsa", jwks: jwksRaw(t, josev4.JSONWebKey{
			Key:       &weakRSA.PublicKey,
			KeyID:     "weak",
			Algorithm: "RS256",
			Use:       "sig",
		})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			//nolint:gosec // G101 false positive: private_key_jwt is an auth-method label.
			_, err := validatePolicy(ClientMetadata{
				RedirectURIs:            []string{"https://rp.test.invalid/cb"},
				TokenEndpointAuthMethod: "private_key_jwt",
				JWKs:                    tc.jwks,
			}, []string{"authorization_code"}, []string{"code"}, nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{})
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			assertInvalidClientMetadata(t, err)
		})
	}
}

func TestValidatePolicy_PrivateKeyJWTAcceptsValidInlineJWKS(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	//nolint:gosec // G101 false positive: private_key_jwt is an auth-method label.
	_, err = validatePolicy(ClientMetadata{
		RedirectURIs:            []string{"https://rp.test.invalid/cb"},
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKs: jwksRaw(t, josev4.JSONWebKey{
			Key:       &key.PublicKey,
			KeyID:     "p256",
			Algorithm: "ES256",
			Use:       "sig",
		}),
	}, []string{"authorization_code"}, []string{"code"}, nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{})
	if err != nil {
		t.Fatalf("validatePolicy: %v", err)
	}
}

func TestValidatePolicy_OutboundEncryptionRequiresUsableInlineJWKS(t *testing.T) {
	t.Parallel()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	base := ClientMetadata{ //nolint:gosec // G101: public JWK metadata fixture, not a credential.
		RedirectURIs:                []string{"https://rp.test.invalid/cb"},
		IDTokenEncryptedResponseAlg: "RSA-OAEP-256",
		IDTokenEncryptedResponseEnc: "A256GCM",
		JWKs: jwksRaw(t, josev4.JSONWebKey{
			Key:       &key.PublicKey,
			KeyID:     "enc-1",
			Algorithm: "RSA-OAEP-256",
			Use:       "enc",
		}),
	}
	if _, err := validatePolicy(base, []string{"authorization_code"}, []string{"code"}, nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{}); err != nil {
		t.Fatalf("validatePolicy(valid outbound encryption key): %v", err)
	}
	base.JWKs = jwksRaw(t, josev4.JSONWebKey{
		Key:       &key.PublicKey,
		KeyID:     "wrong-use",
		Algorithm: "RSA-OAEP-256",
		Use:       "sig",
	})
	if _, err := validatePolicy(base, []string{"authorization_code"}, []string{"code"}, nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{}); err == nil {
		t.Fatal("validatePolicy accepted a JWE key marked use=sig")
	}
}

// unsupportedMemberJWK is a JWK the JOSE layer cannot turn into a key: an
// OKP curve outside the Ed25519 it implements. An RP that offers ECDH-ES
// encryption registers a member of this shape next to the signing key it
// authenticates with.
const unsupportedMemberJWK = `{"kty":"OKP","crv":"X25519","x":"hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo","use":"enc","kid":"enc-1"}`

// TestValidatePolicy_PrivateKeyJWTIgnoresUnsupportedInlineJWK pins RFC 7517
// §5 at registration: a member whose key type this build does not implement
// is ignored, so a client publishing an encryption key next to its signing
// key still registers. The unsupported member is placed first because the
// document-level decode used to fail on it before ever reaching the usable
// key behind it.
func TestValidatePolicy_PrivateKeyJWTIgnoresUnsupportedInlineJWK(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	//nolint:gosec // G101 false positive: private_key_jwt is an auth-method label.
	_, err = validatePolicy(ClientMetadata{
		RedirectURIs:            []string{"https://rp.test.invalid/cb"},
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKs: spliceUnsupportedMember(t, jwksRaw(t, josev4.JSONWebKey{
			Key:       &key.PublicKey,
			KeyID:     "p256",
			Algorithm: "ES256",
			Use:       "sig",
		})),
	}, []string{"authorization_code"}, []string{"code"}, nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{})
	if err != nil {
		t.Fatalf("validatePolicy: %v", err)
	}
}

// TestValidatePolicy_PrivateKeyJWTRejectsOnlyUnsupportedInlineJWK is the
// counterpart: a keyset that leaves no usable key behind is still rejected,
// so registration cannot succeed with a set the OP could never verify with.
func TestValidatePolicy_PrivateKeyJWTRejectsOnlyUnsupportedInlineJWK(t *testing.T) {
	t.Parallel()

	//nolint:gosec // G101 false positive: private_key_jwt is an auth-method label.
	_, err := validatePolicy(ClientMetadata{
		RedirectURIs:            []string{"https://rp.test.invalid/cb"},
		TokenEndpointAuthMethod: "private_key_jwt",
		JWKs:                    []byte(`{"keys":[` + unsupportedMemberJWK + `]}`),
	}, []string{"authorization_code"}, []string{"code"}, nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	assertInvalidClientMetadata(t, err)
}

// spliceUnsupportedMember prepends [unsupportedMemberJWK] to the members of
// set, modelling the keyset an RP publishes when it offers an encryption
// key alongside the signing key it authenticates with.
func spliceUnsupportedMember(tb testing.TB, set []byte) []byte {
	tb.Helper()
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(set, &doc); err != nil {
		tb.Fatalf("unmarshal jwks: %v", err)
	}
	doc.Keys = append([]json.RawMessage{json.RawMessage(unsupportedMemberJWK)}, doc.Keys...)
	raw, err := json.Marshal(doc)
	if err != nil {
		tb.Fatalf("marshal jwks: %v", err)
	}
	return raw
}

func jwksRaw(tb testing.TB, keys ...josev4.JSONWebKey) []byte {
	tb.Helper()
	raw, err := json.Marshal(josev4.JSONWebKeySet{Keys: keys})
	if err != nil {
		tb.Fatalf("json.Marshal JWKS: %v", err)
	}
	return raw
}

func assertInvalidClientMetadata(tb testing.TB, err error) {
	tb.Helper()
	var ve *validationError
	if !errors.As(err, &ve) {
		tb.Fatalf("err=%T %v, want validationError", err, err)
	}
	if ve.code != codeInvalidClientMetadata {
		tb.Fatalf("code=%q want %q", ve.code, codeInvalidClientMetadata)
	}
}

func TestValidatePolicy_RejectsUnsupportedRequestObjectSigningAlg(t *testing.T) {
	t.Parallel()

	_, err := validatePolicy(ClientMetadata{
		RedirectURIs:            []string{"https://rp.test.invalid/cb"},
		RequestObjectSigningAlg: "HS256",
	}, []string{"authorization_code"}, []string{"code"}, nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

func TestValidatePolicy_RejectsUnsupportedTokenEndpointAuthSigningAlg(t *testing.T) {
	t.Parallel()

	//nolint:gosec // G101 false positive: test fixture client metadata, not a credential.
	_, err := validatePolicy(ClientMetadata{
		RedirectURIs:                []string{"https://rp.example.com/cb"},
		TokenEndpointAuthMethod:     "private_key_jwt",
		TokenEndpointAuthSigningAlg: "none",
	}, []string{"authorization_code", "refresh_token"}, []string{"code"}, nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{})
	if err == nil {
		t.Fatal("expected validation error")
	}
	var ve *validationError
	if !errors.As(err, &ve) {
		t.Fatalf("err=%T %v, want validationError", err, err)
	}
	if ve.code != codeInvalidClientMetadata {
		t.Errorf("code=%q want %q", ve.code, codeInvalidClientMetadata)
	}
}

// TestValidatePolicy_AcceptsRequestObjectEncryption pins the v0.9.1
// allow-list for [request_object_encryption_alg / _enc]: every entry
// on the JOSE wrapper's allow-list flows through the DCR validator
// unchanged when both halves are present. The test fails closed if
// the allow-list grows past the validator's source-of-truth set
// (jose.AllowedJWEAlgs / AllowedJWEEncs) without a corresponding
// update.
//
// Half-pair cases (alg-only / enc-only) are NOT in this table — they
// are pinned as rejections by [TestRegister_JWEAlgEncPair_Matrix] in
// metadata_validate_encryption_test.go (M6 closes the prior
// admit-then-runtime-reject gap).
func TestValidatePolicy_AcceptsRequestObjectEncryption(t *testing.T) {
	t.Parallel()

	cases := []struct {
		alg, enc string
	}{
		{alg: "RSA-OAEP-256", enc: "A256GCM"},
		{alg: "ECDH-ES", enc: "A128GCM"},
		{alg: "ECDH-ES+A128KW", enc: "A128GCM"},
		{alg: "ECDH-ES+A256KW", enc: "A256GCM"},
	}
	for _, tc := range cases {
		t.Run(tc.alg+"/"+tc.enc, func(t *testing.T) {
			t.Parallel()
			_, err := validatePolicy(ClientMetadata{
				RedirectURIs:               []string{"https://rp.test.invalid/cb"},
				RequestObjectEncryptionAlg: tc.alg,
				RequestObjectEncryptionEnc: tc.enc,
			}, []string{"authorization_code"}, []string{"code"}, nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{})
			if err != nil {
				t.Fatalf("validatePolicy: %v", err)
			}
		})
	}
}

// TestValidatePolicy_RejectsRequestObjectEncryptionOutsideAllowlist pins
// the negative half: any value outside the allow-list MUST surface
// invalid_client_metadata so a registration probe cannot land an alg
// the JAR verifier would later refuse as
// [jar.ErrEncryptionAlgNotAllowed].
func TestValidatePolicy_RejectsRequestObjectEncryptionOutsideAllowlist(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, alg, enc, want string
	}{
		{name: "alg-RSA1_5", alg: "RSA1_5", enc: "A256GCM", want: "request_object_encryption_alg"},
		{name: "alg-A128KW", alg: "A128KW", enc: "A128GCM", want: "request_object_encryption_alg"},
		{name: "enc-CBC", alg: "RSA-OAEP-256", enc: "A128CBC-HS256", want: "request_object_encryption_enc"},
		{name: "enc-A192", alg: "RSA-OAEP-256", enc: "A192GCM", want: "request_object_encryption_enc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := validatePolicy(ClientMetadata{
				RedirectURIs:               []string{"https://rp.test.invalid/cb"},
				RequestObjectEncryptionAlg: tc.alg,
				RequestObjectEncryptionEnc: tc.enc,
			}, []string{"authorization_code"}, []string{"code"}, nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{})
			if err == nil {
				t.Fatal("expected validation error, got nil")
			}
			var ve *validationError
			if !errors.As(err, &ve) {
				t.Fatalf("error %v is not *validationError", err)
			}
			if ve.code != codeInvalidClientMetadata {
				t.Errorf("code = %q, want %q", ve.code, codeInvalidClientMetadata)
			}
			if !strings.Contains(ve.description, tc.want) {
				t.Errorf("description %q must contain %q", ve.description, tc.want)
			}
		})
	}
}

// TestValidatePolicy_AcceptsResponseEncryption pins the v0.9.1 allow-list
// for the four outbound-encryption metadata pairs (id_token, userinfo,
// JARM authorization, introspection). Each path mirrors
// [TestValidatePolicy_AcceptsRequestObjectEncryption]: every alg/enc on
// the JOSE wrapper's allow-list flows through unchanged when both
// halves are present, plus the "both empty" carve-out (the client opts
// out of encryption for that response type). The table is keyed by
// metadata path so a regression in one validator surfaces against the
// path it ought to.
//
// Half-pair cases are pinned as rejections by
// [TestRegister_JWEAlgEncPair_Matrix] in
// metadata_validate_encryption_test.go (M6: half-pair admits used to
// land here and fail at first-use; v0.9.1 rejects them at registration).
func TestValidatePolicy_AcceptsResponseEncryption(t *testing.T) {
	t.Parallel()

	combos := []struct {
		alg, enc string
	}{
		{alg: "RSA-OAEP-256", enc: "A256GCM"},
		{alg: "ECDH-ES", enc: "A128GCM"},
		{alg: "ECDH-ES+A128KW", enc: "A128GCM"},
		{alg: "ECDH-ES+A256KW", enc: "A256GCM"},
		{alg: "", enc: ""},
	}
	paths := []struct {
		name string
		set  func(m *ClientMetadata, alg, enc string)
	}{
		{
			name: "id_token",
			set: func(m *ClientMetadata, alg, enc string) {
				m.IDTokenEncryptedResponseAlg = alg
				m.IDTokenEncryptedResponseEnc = enc
			},
		},
		{
			name: "userinfo",
			set: func(m *ClientMetadata, alg, enc string) {
				m.UserInfoEncryptedResponseAlg = alg
				m.UserInfoEncryptedResponseEnc = enc
			},
		},
		{
			name: "authorization",
			set: func(m *ClientMetadata, alg, enc string) {
				m.AuthorizationEncryptedResponseAlg = alg
				m.AuthorizationEncryptedResponseEnc = enc
			},
		},
		{
			name: "introspection",
			set: func(m *ClientMetadata, alg, enc string) {
				m.IntrospectionEncryptedResponseAlg = alg
				m.IntrospectionEncryptedResponseEnc = enc
			},
		},
	}
	for _, p := range paths {
		for _, c := range combos {
			t.Run(p.name+"/"+c.alg+"/"+c.enc, func(t *testing.T) {
				t.Parallel()
				m := ClientMetadata{
					RedirectURIs: []string{"https://rp.test.invalid/cb"},
				}
				p.set(&m, c.alg, c.enc)
				if c.alg != "" {
					m.JWKsURI = "https://rp.test.invalid/jwks.json"
				}
				if _, err := validatePolicy(m,
					[]string{"authorization_code"}, []string{"code"},
					nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{}); err != nil {
					t.Fatalf("validatePolicy: %v", err)
				}
			})
		}
	}
}

// TestValidatePolicy_RejectsResponseEncryptionOutsideAllowlist pins the
// negative half across the four outbound-encryption metadata pairs:
// any alg/enc value off the v0.9.1 allow-list MUST return
// invalid_client_metadata, and the description MUST name the offending
// wire field so embedders can self-correct.
func TestValidatePolicy_RejectsResponseEncryptionOutsideAllowlist(t *testing.T) {
	t.Parallel()

	type combo struct {
		name      string
		alg, enc  string
		wantField string
	}
	paths := []struct {
		name     string
		algField string
		encField string
		applyAlg func(m *ClientMetadata, alg, enc string)
	}{
		{
			name:     "id_token",
			algField: "id_token_encrypted_response_alg",
			encField: "id_token_encrypted_response_enc",
			applyAlg: func(m *ClientMetadata, alg, enc string) {
				m.IDTokenEncryptedResponseAlg = alg
				m.IDTokenEncryptedResponseEnc = enc
			},
		},
		{
			name:     "userinfo",
			algField: "userinfo_encrypted_response_alg",
			encField: "userinfo_encrypted_response_enc",
			applyAlg: func(m *ClientMetadata, alg, enc string) {
				m.UserInfoEncryptedResponseAlg = alg
				m.UserInfoEncryptedResponseEnc = enc
			},
		},
		{
			name:     "authorization",
			algField: "authorization_encrypted_response_alg",
			encField: "authorization_encrypted_response_enc",
			applyAlg: func(m *ClientMetadata, alg, enc string) {
				m.AuthorizationEncryptedResponseAlg = alg
				m.AuthorizationEncryptedResponseEnc = enc
			},
		},
		{
			name:     "introspection",
			algField: "introspection_encrypted_response_alg",
			encField: "introspection_encrypted_response_enc",
			applyAlg: func(m *ClientMetadata, alg, enc string) {
				m.IntrospectionEncryptedResponseAlg = alg
				m.IntrospectionEncryptedResponseEnc = enc
			},
		},
	}
	for _, p := range paths {
		combos := []combo{
			{name: "alg-RSA1_5", alg: "RSA1_5", enc: "A256GCM", wantField: p.algField},
			{name: "alg-A128KW", alg: "A128KW", enc: "A128GCM", wantField: p.algField},
			{name: "enc-CBC", alg: "RSA-OAEP-256", enc: "A128CBC-HS256", wantField: p.encField},
			{name: "enc-A192", alg: "RSA-OAEP-256", enc: "A192GCM", wantField: p.encField},
		}
		for _, c := range combos {
			t.Run(p.name+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				m := ClientMetadata{
					RedirectURIs: []string{"https://rp.test.invalid/cb"},
				}
				p.applyAlg(&m, c.alg, c.enc)
				_, err := validatePolicy(m,
					[]string{"authorization_code"}, []string{"code"},
					nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{})
				if err == nil {
					t.Fatal("expected validation error, got nil")
				}
				var ve *validationError
				if !errors.As(err, &ve) {
					t.Fatalf("error %v is not *validationError", err)
				}
				if ve.code != codeInvalidClientMetadata {
					t.Errorf("code = %q, want %q", ve.code, codeInvalidClientMetadata)
				}
				if !strings.Contains(ve.description, c.wantField) {
					t.Errorf("description %q must contain %q", ve.description, c.wantField)
				}
			})
		}
	}
}

func TestValidatePolicy_RejectsPairwiseMultiHostWithoutSectorIdentifier(t *testing.T) {
	t.Parallel()

	_, err := validatePolicy(ClientMetadata{
		RedirectURIs: []string{
			"https://a.example.com/cb",
			"https://b.example.com/cb",
		},
		SubjectType: "pairwise",
	}, []string{"authorization_code"}, []string{"code"}, nil, false, nil, nil, true, false, false, internaljose.JWEPolicy{})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

func TestValidatePolicy_RejectsCodeResponseTypeWithoutAuthorizationCodeGrant(t *testing.T) {
	t.Parallel()

	_, err := validatePolicy(ClientMetadata{
		RedirectURIs:    []string{"https://rp.test.invalid/cb"},
		GrantTypes:      []string{"implicit"},
		ResponseTypes:   []string{"code"},
		ApplicationType: "web",
	}, []string{"authorization_code", "implicit"}, []string{"code", "id_token"}, nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

func TestValidatePolicy_RejectsImplicitResponseTypeWithoutImplicitGrant(t *testing.T) {
	t.Parallel()

	_, err := validatePolicy(ClientMetadata{
		RedirectURIs:  []string{"https://rp.test.invalid/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"id_token"},
	}, []string{"authorization_code", "implicit"}, []string{"code", "id_token"}, nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

func TestValidatePolicy_RejectsHybridResponseTypeWithoutImplicitGrant(t *testing.T) {
	t.Parallel()

	_, err := validatePolicy(ClientMetadata{
		RedirectURIs:  []string{"https://rp.test.invalid/cb"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code id_token"},
	}, []string{"authorization_code", "implicit"}, []string{"code", "id_token", "code id_token"}, nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{})
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

// TestValidatePostLogoutRedirectURIs walks the OIDC RP-Initiated Logout
// 1.0 §3 + RFC 8252 §7.3 matrix the helper enforces: native clients may
// use https, loopback http (textual "localhost" is admitted
// unconditionally for native), or a reverse-DNS custom scheme. Web
// clients require https, with the AllowLocalhostLoopback gate widening
// the loopback http carve-out to "localhost". Every failure MUST
// return invalid_client_metadata (not invalid_redirect_uri) and the
// description MUST contain both "post_logout_redirect_uris" and
// "loopback" so embedders can self-correct.
func TestValidatePostLogoutRedirectURIs(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name             string
		uri              string
		applicationType  string
		allowLocalhost   bool
		wantErr          bool
		wantDescContains []string
	}{
		{name: "native-https", uri: "https://rp.example.com/logout", applicationType: "native"},
		{name: "native-http-127", uri: "http://127.0.0.1/logout", applicationType: "native"},
		{name: "native-http-127-port", uri: "http://127.0.0.1:53682/logout", applicationType: "native"},
		{name: "native-http-ipv6", uri: "http://[::1]/logout", applicationType: "native"},
		{name: "native-http-localhost-no-gate", uri: "http://localhost/logout", applicationType: "native"},
		{name: "native-custom-scheme", uri: "com.example.app:/logout", applicationType: "native"},
		{
			name:             "native-http-public-host",
			uri:              "http://rp.example.com/logout",
			applicationType:  "native",
			wantErr:          true,
			wantDescContains: []string{"post_logout_redirect_uris", "loopback"},
		},
		{
			name:             "native-http-private-ip",
			uri:              "http://10.0.0.1/logout",
			applicationType:  "native",
			wantErr:          true,
			wantDescContains: []string{"post_logout_redirect_uris", "loopback"},
		},
		{
			name:             "native-non-reverse-dns-scheme",
			uri:              "myapp:/logout",
			applicationType:  "native",
			wantErr:          true,
			wantDescContains: []string{"post_logout_redirect_uris", "loopback"},
		},
		{name: "web-https", uri: "https://rp.example.com/logout", applicationType: "web"},
		{
			name:             "web-https-without-authority",
			uri:              "https:/logout",
			applicationType:  "web",
			wantErr:          true,
			wantDescContains: []string{"post_logout_redirect_uris", "loopback"},
		},
		{
			name:             "web-https-empty-hostname",
			uri:              "https://:443/logout",
			applicationType:  "web",
			wantErr:          true,
			wantDescContains: []string{"post_logout_redirect_uris", "loopback"},
		},
		{
			name:             "web-https-with-userinfo",
			uri:              "https://user@rp.example.com/logout",
			applicationType:  "web",
			wantErr:          true,
			wantDescContains: []string{"post_logout_redirect_uris", "loopback"},
		},
		{
			name:             "web-http-public-host",
			uri:              "http://rp.example.com/logout",
			applicationType:  "web",
			wantErr:          true,
			wantDescContains: []string{"post_logout_redirect_uris", "loopback"},
		},
		{
			name:             "web-http-localhost-default",
			uri:              "http://localhost/logout",
			applicationType:  "web",
			wantErr:          true,
			wantDescContains: []string{"post_logout_redirect_uris", "loopback"},
		},
		{name: "web-http-localhost-allowed", uri: "http://localhost/logout", applicationType: "web", allowLocalhost: true},
		{name: "web-http-127", uri: "http://127.0.0.1/logout", applicationType: "web"},
		{
			name:             "web-fragment",
			uri:              "https://rp.example.com/logout#x",
			applicationType:  "web",
			wantErr:          true,
			wantDescContains: []string{"post_logout_redirect_uris", "loopback"},
		},
		{
			name:             "relative",
			uri:              "/logout",
			applicationType:  "web",
			wantErr:          true,
			wantDescContains: []string{"post_logout_redirect_uris", "loopback"},
		},
		{
			name:             "empty-entry",
			uri:              "",
			applicationType:  "web",
			wantErr:          true,
			wantDescContains: []string{"post_logout_redirect_uris", "loopback"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validatePostLogoutRedirectURIs([]string{tc.uri}, tc.applicationType, tc.allowLocalhost)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("validatePostLogoutRedirectURIs(%q, %q) unexpected error: %v", tc.uri, tc.applicationType, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validatePostLogoutRedirectURIs(%q, %q) = nil, want error", tc.uri, tc.applicationType)
			}
			var ve *validationError
			if !errors.As(err, &ve) {
				t.Fatalf("error %v is not *validationError", err)
			}
			if ve.code != codeInvalidClientMetadata {
				t.Errorf("error code = %q, want %q", ve.code, codeInvalidClientMetadata)
			}
			for _, want := range tc.wantDescContains {
				if !strings.Contains(ve.description, want) {
					t.Errorf("error description %q must contain %q", ve.description, want)
				}
			}
		})
	}
}

// TestValidateMetadataURIs_RejectsUserinfo pins the rule that every
// metadata URL the OP fetches or audits MUST refuse a URL that
// embeds userinfo (`https://trusted.example@evil.example/...`).
// Go's `url.Parse` resolves the host to `evil.example` while a
// human or alternative parser can read `trusted.example` — exactly
// the kind of parser-confusion the SSRF / allowlist policy must
// short-circuit.
//
// The matrix walks every field guarded by [validateHTTPSAbsoluteURI]
// plus the [validateRequestURI] paths (request_uris); the
// fragment-allowed quirk of request_uris does not relax the userinfo
// rule.
func TestValidateMetadataURIs_RejectsUserinfo(t *testing.T) {
	t.Parallel()

	const evilURL = "https://trusted.example@evil.example/foo"
	const evilFragmentURL = "https://trusted.example@evil.example/req#sha256-xyz"

	cases := []struct {
		name string
		mut  func(*ClientMetadata)
	}{
		{"client_uri", func(m *ClientMetadata) { m.ClientURI = evilURL }},
		{"logo_uri", func(m *ClientMetadata) { m.LogoURI = evilURL }},
		{"policy_uri", func(m *ClientMetadata) { m.PolicyURI = evilURL }},
		{"tos_uri", func(m *ClientMetadata) { m.TosURI = evilURL }},
		{"jwks_uri", func(m *ClientMetadata) { m.JWKsURI = evilURL }},
		{"sector_identifier_uri", func(m *ClientMetadata) { m.SectorIdentifierURI = evilURL }},
		{"initiate_login_uri", func(m *ClientMetadata) { m.InitiateLoginURI = evilURL }},
		{"request_uris", func(m *ClientMetadata) { m.RequestURIs = []string{evilFragmentURL} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := ClientMetadata{RedirectURIs: []string{"https://rp.test.invalid/cb"}}
			tc.mut(&m)
			_, err := validatePolicy(m,
				[]string{"authorization_code"}, []string{"code"}, nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{})
			if err == nil {
				t.Fatalf("%s: expected validation error for userinfo URL %q", tc.name, evilURL)
			}
			var ve *validationError
			if !errors.As(err, &ve) {
				t.Fatalf("%s: error %v is not *validationError", tc.name, err)
			}
			if ve.code != codeInvalidClientMetadata {
				t.Errorf("%s: code=%q want %q", tc.name, ve.code, codeInvalidClientMetadata)
			}
			if !strings.Contains(ve.description, "must not contain userinfo") {
				t.Errorf("%s: description=%q want it to mention userinfo", tc.name, ve.description)
			}
			if !strings.Contains(ve.description, tc.name) {
				t.Errorf("%s: description=%q want it to mention the field name", tc.name, ve.description)
			}
		})
	}
}

func TestValidateMetadataURIs_RejectsEmptyHostname(t *testing.T) {
	t.Parallel()

	const emptyHostnameURL = "https://:443/value"
	cases := []struct {
		name string
		mut  func(*ClientMetadata)
	}{
		{"client_uri", func(m *ClientMetadata) { m.ClientURI = emptyHostnameURL }},
		{"logo_uri", func(m *ClientMetadata) { m.LogoURI = emptyHostnameURL }},
		{"policy_uri", func(m *ClientMetadata) { m.PolicyURI = emptyHostnameURL }},
		{"tos_uri", func(m *ClientMetadata) { m.TosURI = emptyHostnameURL }},
		{"jwks_uri", func(m *ClientMetadata) { m.JWKsURI = emptyHostnameURL }},
		{"sector_identifier_uri", func(m *ClientMetadata) { m.SectorIdentifierURI = emptyHostnameURL }},
		{"initiate_login_uri", func(m *ClientMetadata) { m.InitiateLoginURI = emptyHostnameURL }},
		{"request_uris", func(m *ClientMetadata) { m.RequestURIs = []string{emptyHostnameURL + "#sha256-xyz"} }},
		{"backchannel_logout_uri", func(m *ClientMetadata) { m.BackchannelLogoutURI = emptyHostnameURL }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := ClientMetadata{RedirectURIs: []string{"https://rp.test.invalid/cb"}}
			tc.mut(&m)
			_, err := validatePolicy(m,
				[]string{"authorization_code"}, []string{"code"}, nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{})
			if err == nil {
				t.Fatalf("%s: accepted URL with empty hostname %q", tc.name, emptyHostnameURL)
			}
			var ve *validationError
			if !errors.As(err, &ve) {
				t.Fatalf("%s: error %v is not *validationError", tc.name, err)
			}
			if ve.code != codeInvalidClientMetadata {
				t.Errorf("%s: code=%q want %q", tc.name, ve.code, codeInvalidClientMetadata)
			}
			if !strings.Contains(ve.description, "must include a host") {
				t.Errorf("%s: description=%q want host diagnostic", tc.name, ve.description)
			}
		})
	}
}

// TestValidateBackchannelLogoutURI pins the rule that DCR / RM
// MUST validate `backchannel_logout_uri` at registration time so a
// plaintext / fragment-bearing / userinfo-bearing logout endpoint is
// rejected before the deliverer ever loads it. The check shares the
// same [validateHTTPSAbsoluteURI] helper with client_uri / jwks_uri
// / sector_identifier_uri so the URL-safety policy is uniform.
//
// The matrix also pins that `backchannel_logout_session_required=true`
// is rejected even with a delivery URL. The current grant model cannot
// recover an RP-specific SID, so accepting the flag would create a
// capability lie or leak an unrelated browser-session identifier.
func TestValidateBackchannelLogoutURI(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		mut     func(*ClientMetadata)
		wantErr string
	}{
		{
			name: "https-host",
			mut: func(m *ClientMetadata) {
				m.BackchannelLogoutURI = "https://rp.example.com/logout"
			},
		},
		{
			name: "http-rejected",
			mut: func(m *ClientMetadata) {
				m.BackchannelLogoutURI = "http://rp.example.com/logout"
			},
			wantErr: "must use https",
		},
		{
			name: "fragment-rejected",
			mut: func(m *ClientMetadata) {
				m.BackchannelLogoutURI = "https://rp.example.com/logout#x"
			},
			wantErr: "must not contain a fragment",
		},
		{
			name: "userinfo-rejected",
			mut: func(m *ClientMetadata) {
				m.BackchannelLogoutURI = "https://trusted.example@evil.example/logout"
			},
			wantErr: "must not contain userinfo",
		},
		{
			name: "session-required-without-uri-rejected",
			mut: func(m *ClientMetadata) {
				m.BackchannelLogoutSessionRequired = true
			},
			wantErr: "not supported",
		},
		{
			name: "session-required-with-uri-rejected",
			mut: func(m *ClientMetadata) {
				m.BackchannelLogoutURI = "https://rp.example.com/logout"
				m.BackchannelLogoutSessionRequired = true
			},
			wantErr: "not supported",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := ClientMetadata{RedirectURIs: []string{"https://rp.test.invalid/cb"}}
			tc.mut(&m)
			_, err := validatePolicy(m,
				[]string{"authorization_code"}, []string{"code"}, nil, false, nil, nil, false, false, false, internaljose.JWEPolicy{})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validatePolicy unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validatePolicy: expected %q in error, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q must contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestValidateBackchannelLogoutURI_RejectsEmptyHostnameInDevMode(t *testing.T) {
	t.Parallel()

	if err := validateBackchannelLogoutURI("https://:443/logout", true); err == nil {
		t.Fatal("validateBackchannelLogoutURI accepted an HTTPS authority with an empty hostname")
	}
}

// TestValidatePostLogoutRedirectURIs_EmptySliceAccepted confirms the
// helper treats an absent post_logout_redirect_uris list as "no
// post-logout target" rather than an error: the field is optional per
// OIDC RP-Initiated Logout 1.0 §3 and /end_session simply rejects any
// post_logout_redirect_uri request parameter when the list is empty.
func TestValidatePostLogoutRedirectURIs_EmptySliceAccepted(t *testing.T) {
	t.Parallel()
	if err := validatePostLogoutRedirectURIs(nil, "web", false); err != nil {
		t.Fatalf("validatePostLogoutRedirectURIs(nil, web) unexpected error: %v", err)
	}
}

// TestDefaultScopeIfEmpty_OpenRegistrationDefault pins the
// selection order at the unit level: open-registration
// scope-omitted requests receive the embedder default (empty when
// unset, the configured list when set), the IAT-bound allowlist
// always wins when present, and the public-catalog fallback fires
// only on the IAT-without-allowlist branch.
func TestDefaultScopeIfEmpty_OpenRegistrationDefault(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name             string
		scope            string
		iatScopes        []string
		openRegistration bool
		openDefault      []string
		want             string
	}{
		{name: "explicit-scope-wins", scope: "openid", iatScopes: []string{"profile"}, openRegistration: true, openDefault: []string{"email"}, want: "openid"},
		{name: "iat-allowlist-wins-over-open-default", iatScopes: []string{"openid"}, openRegistration: true, openDefault: []string{"email"}, want: "openid"},
		{name: "open-no-default-empty", openRegistration: true, want: ""},
		{name: "open-with-default", openRegistration: true, openDefault: []string{"openid", "profile"}, want: "openid profile"},
		{name: "iat-without-allowlist-no-fallback-when-registry-nil", openRegistration: false, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := defaultScopeIfEmpty(tc.scope, tc.iatScopes, tc.openRegistration, tc.openDefault, nil)
			if got != tc.want {
				t.Errorf("defaultScopeIfEmpty=%q want %q", got, tc.want)
			}
		})
	}
}

func TestDefaultScopeIfEmpty_IATDefaultSkipsAllowedClientsRestrictedScopes(t *testing.T) {
	t.Parallel()

	registry := scoperegistry.New([]scoperegistry.Entry{
		{Name: "openid", Public: true},
		{Name: "profile", Public: true},
		{Name: "billing:write", Public: true, AllowedClients: []string{"svc-billing"}},
	})
	got := defaultScopeIfEmpty("", nil, false, nil, registry)
	if got != "openid profile" {
		t.Fatalf("defaultScopeIfEmpty=%q want %q", got, "openid profile")
	}
}
