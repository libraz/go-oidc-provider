package registrationendpoint

import (
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	internaljose "github.com/libraz/go-oidc-provider/internal/jose"
)

// TestValidatePolicy_TLSClientAuthMetadata pins the RFC 8705 §2
// registration rules: tls_client_auth takes exactly one well-formed
// matcher, self_signed_tls_client_auth exactly one key source, no other
// method carries a matcher, and neither mTLS method is admitted on an OP
// without feature.MTLS.
func TestValidatePolicy_TLSClientAuthMetadata(t *testing.T) {
	t.Parallel()

	const jwksURI = "https://rp.test.invalid/jwks.json"
	tlsAuth := string(clientauth.MethodTLSClientAuth)
	selfSigned := string(clientauth.MethodSelfSignedTLSClientAuth)
	mtlsOn := profilePolicy{mtlsClientAuth: true}
	cases := []struct {
		name    string
		m       ClientMetadata
		policy  profilePolicy
		wantErr string
	}{
		{"subject_dn", ClientMetadata{TokenEndpointAuthMethod: tlsAuth, TLSClientAuthSubjectDN: "CN=rp"}, mtlsOn, ""},
		{"san_dns", ClientMetadata{TokenEndpointAuthMethod: tlsAuth, TLSClientAuthSANDNS: "rp.example.com"}, mtlsOn, ""},
		{"san_uri", ClientMetadata{TokenEndpointAuthMethod: tlsAuth, TLSClientAuthSANURI: "spiffe://example.com/rp"}, mtlsOn, ""},
		{"san_ip", ClientMetadata{TokenEndpointAuthMethod: tlsAuth, TLSClientAuthSANIP: "2001:db8::1"}, mtlsOn, ""},
		{"san_email", ClientMetadata{TokenEndpointAuthMethod: tlsAuth, TLSClientAuthSANEmail: "rp@example.com"}, mtlsOn, ""},
		{"no matcher", ClientMetadata{TokenEndpointAuthMethod: tlsAuth}, mtlsOn, "exactly one of"},
		{"two matchers", ClientMetadata{
			TokenEndpointAuthMethod: tlsAuth, TLSClientAuthSubjectDN: "CN=rp", TLSClientAuthSANDNS: "rp.example.com",
		}, mtlsOn, "exactly one of"},
		{"san_ip not an IP", ClientMetadata{TokenEndpointAuthMethod: tlsAuth, TLSClientAuthSANIP: "rp.example.com"}, mtlsOn, "san_ip"},
		{"san_uri relative", ClientMetadata{TokenEndpointAuthMethod: tlsAuth, TLSClientAuthSANURI: "/rp"}, mtlsOn, "san_uri"},
		{"self_signed jwks_uri", ClientMetadata{TokenEndpointAuthMethod: selfSigned, JWKsURI: jwksURI}, mtlsOn, ""},
		{"self_signed no keys", ClientMetadata{TokenEndpointAuthMethod: selfSigned}, mtlsOn, "jwks or jwks_uri"},
		{"self_signed with matcher", ClientMetadata{
			TokenEndpointAuthMethod: selfSigned, JWKsURI: jwksURI, TLSClientAuthSANDNS: "rp.example.com",
		}, mtlsOn, "tls_client_auth only"},
		{"private_key_jwt with matcher", ClientMetadata{ //nolint:gosec // G101 false positive: auth-method metadata, not a credential.
			TokenEndpointAuthMethod: "private_key_jwt", JWKsURI: jwksURI, TLSClientAuthSubjectDN: "CN=rp",
		}, mtlsOn, "tls_client_auth only"},
		{"tls_client_auth without feature", ClientMetadata{TokenEndpointAuthMethod: tlsAuth, TLSClientAuthSubjectDN: "CN=rp"}, profilePolicy{}, "not supported"},
		{"self_signed without feature", ClientMetadata{TokenEndpointAuthMethod: selfSigned, JWKsURI: jwksURI}, profilePolicy{}, "not supported"},
		{"profile excludes", ClientMetadata{TokenEndpointAuthMethod: tlsAuth, TLSClientAuthSubjectDN: "CN=rp"}, profilePolicy{
			mtlsClientAuth: true, authMethods: []clientauth.Method{clientauth.MethodPrivateKeyJWT},
		}, "not allowed by active profile"},
		{"profile admits", ClientMetadata{TokenEndpointAuthMethod: tlsAuth, TLSClientAuthSubjectDN: "CN=rp"}, profilePolicy{
			mtlsClientAuth: true, authMethods: []clientauth.Method{clientauth.MethodPrivateKeyJWT, clientauth.MethodTLSClientAuth},
		}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := tc.m
			m.RedirectURIs = []string{"https://rp.test.invalid/cb"}
			_, err := validatePolicy(m, []string{"authorization_code"}, []string{"code"}, nil, nil,
				false, false, false, internaljose.JWEPolicy{}, tc.policy)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validatePolicy: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validatePolicy accepted; want error containing %q", tc.wantErr)
			}
			assertInvalidClientMetadata(t, err)
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestValidatePolicy_StaticMTLSRejectionNamesSeedTypes pins the static
// seed wording: an mTLS method without feature.MTLS names the flag and the
// seed types, and a profile rejection names the mTLS seed types when the
// profile would admit them with the flag on.
func TestValidatePolicy_StaticMTLSRejectionNamesSeedTypes(t *testing.T) {
	t.Parallel()

	m := ClientMetadata{
		RedirectURIs:            []string{"https://rp.test.invalid/cb"},
		TokenEndpointAuthMethod: string(clientauth.MethodTLSClientAuth),
		TLSClientAuthSubjectDN:  "CN=rp",
	}
	_, err := validatePolicy(m, []string{"authorization_code"}, []string{"code"}, nil, nil,
		false, false, false, internaljose.JWEPolicy{}, profilePolicy{static: true})
	for _, want := range []string{"WithFeature(feature.MTLS)", "op.TLSClientAuthClient", "op.SelfSignedTLSClientAuthClient"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("feature off: error %v does not name %s", err, want)
		}
	}

	m.TokenEndpointAuthMethod = "client_secret_basic"
	m.TLSClientAuthSubjectDN = ""
	_, err = validatePolicy(m, []string{"authorization_code"}, []string{"code"}, nil, nil,
		false, false, false, internaljose.JWEPolicy{}, profilePolicy{
			static: true, profileName: "profile.FAPI2Baseline", profileAdmitsMTLS: true,
			authMethods: []clientauth.Method{clientauth.MethodPrivateKeyJWT},
		})
	for _, want := range []string{"profile.FAPI2Baseline", "op.PrivateKeyJWTClient", "op.TLSClientAuthClient", "WithFeature(feature.MTLS)"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("profile rejection: error %v does not name %s", err, want)
		}
	}
}
