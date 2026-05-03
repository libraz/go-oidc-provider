//nolint:testpackage // exercises unexported validatePolicy
package registrationendpoint

import (
	"errors"
	"strings"
	"testing"
)

func TestValidatePolicy_RejectsJWKSAndJWKSURI(t *testing.T) {
	t.Parallel()

	_, err := validatePolicy(ClientMetadata{
		RedirectURIs: []string{"https://rp.test.invalid/cb"},
		JWKs:         []byte(`{"keys":[]}`),
		JWKsURI:      "https://rp.test.invalid/jwks.json",
	}, []string{"authorization_code"}, []string{"code"}, nil, nil, false, false)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

func TestValidatePolicy_RejectsHTTPClientURI(t *testing.T) {
	t.Parallel()

	_, err := validatePolicy(ClientMetadata{
		RedirectURIs: []string{"https://rp.test.invalid/cb"},
		ClientURI:    "http://rp.test.invalid",
	}, []string{"authorization_code"}, []string{"code"}, nil, nil, false, false)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

func TestValidatePolicy_RejectsUnsupportedRequestObjectSigningAlg(t *testing.T) {
	t.Parallel()

	_, err := validatePolicy(ClientMetadata{
		RedirectURIs:            []string{"https://rp.test.invalid/cb"},
		RequestObjectSigningAlg: "HS256",
	}, []string{"authorization_code"}, []string{"code"}, nil, nil, false, false)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

// TestValidatePolicy_AcceptsRequestObjectEncryption pins the v0.9.1
// allow-list for [request_object_encryption_alg / _enc]: every entry on
// the JOSE wrapper's allow-list flows through the DCR validator
// unchanged. The test fails closed if the allow-list grows past the
// validator's hard-coded set without a corresponding update.
func TestValidatePolicy_AcceptsRequestObjectEncryption(t *testing.T) {
	t.Parallel()

	cases := []struct {
		alg, enc string
	}{
		{alg: "RSA-OAEP-256", enc: "A256GCM"},
		{alg: "ECDH-ES", enc: "A128GCM"},
		{alg: "ECDH-ES+A128KW", enc: "A128GCM"},
		{alg: "ECDH-ES+A256KW", enc: "A256GCM"},
		{alg: "RSA-OAEP-256", enc: ""},
		{alg: "", enc: "A256GCM"},
	}
	for _, tc := range cases {
		t.Run(tc.alg+"/"+tc.enc, func(t *testing.T) {
			t.Parallel()
			_, err := validatePolicy(ClientMetadata{
				RedirectURIs:               []string{"https://rp.test.invalid/cb"},
				RequestObjectEncryptionAlg: tc.alg,
				RequestObjectEncryptionEnc: tc.enc,
			}, []string{"authorization_code"}, []string{"code"}, nil, nil, false, false)
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
			}, []string{"authorization_code"}, []string{"code"}, nil, nil, false, false)
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
// the JOSE wrapper's allow-list flows through unchanged, plus the
// "alg without enc" / "enc without alg" / "both empty" carve-outs OIDC
// §6.1 admits. The table is keyed by metadata path so a regression in
// one validator surfaces against the path it ought to.
func TestValidatePolicy_AcceptsResponseEncryption(t *testing.T) {
	t.Parallel()

	combos := []struct {
		alg, enc string
	}{
		{alg: "RSA-OAEP-256", enc: "A256GCM"},
		{alg: "ECDH-ES", enc: "A128GCM"},
		{alg: "ECDH-ES+A128KW", enc: "A128GCM"},
		{alg: "ECDH-ES+A256KW", enc: "A256GCM"},
		{alg: "RSA-OAEP-256", enc: ""},
		{alg: "", enc: "A256GCM"},
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
				if _, err := validatePolicy(m,
					[]string{"authorization_code"}, []string{"code"},
					nil, nil, false, false); err != nil {
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
					nil, nil, false, false)
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
	}, []string{"authorization_code"}, []string{"code"}, nil, nil, true, false)
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
	}, []string{"authorization_code", "implicit"}, []string{"code", "id_token"}, nil, nil, false, false)
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
	}, []string{"authorization_code", "implicit"}, []string{"code", "id_token"}, nil, nil, false, false)
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
	}, []string{"authorization_code", "implicit"}, []string{"code", "id_token", "code id_token"}, nil, nil, false, false)
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
