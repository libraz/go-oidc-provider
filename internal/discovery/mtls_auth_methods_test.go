package discovery_test

import (
	"slices"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/discovery"
)

// TestBuild_MTLSClientAuthMethodsFollowTheFeature pins that the token,
// introspection and revocation auth-method lists carry tls_client_auth
// and self_signed_tls_client_auth exactly when feature.MTLS is on, and
// that a profile allow-list naming them keeps them through narrowing.
func TestBuild_MTLSClientAuthMethodsFollowTheFeature(t *testing.T) {
	t.Parallel()

	mtlsMethods := []string{"tls_client_auth", "self_signed_tls_client_auth"}
	for _, tc := range []struct {
		name    string
		mtls    bool
		profile []string
		want    bool
	}{
		{"feature off", false, nil, false},
		{"feature on", true, nil, true},
		{"feature on, FAPI allow-list", true, []string{"private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"}, true},
		{"feature on, allow-list without mTLS", true, []string{"private_key_jwt"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := discovery.Build(discovery.Input{
				Issuer:                    "https://idp.example.com",
				Endpoints:                 discovery.EndpointPaths{JWKS: "/jwks", Token: "/token", Introspect: "/introspect", Revoke: "/revoke"},
				Features:                  discovery.Features{MTLS: tc.mtls, Introspect: true, Revoke: true},
				ProfileAllowedAuthMethods: tc.profile,
			})
			for name, list := range map[string][]string{
				"token_endpoint_auth_methods_supported":         doc.TokenEndpointAuthMethodsSupported,
				"introspection_endpoint_auth_methods_supported": doc.IntrospectionEndpointAuthMethodsSupported,
				"revocation_endpoint_auth_methods_supported":    doc.RevocationEndpointAuthMethodsSupported,
			} {
				for _, m := range mtlsMethods {
					if slices.Contains(list, m) != tc.want {
						t.Errorf("%s=%v: %s present=%v, want %v", name, list, m, !tc.want, tc.want)
					}
				}
			}
			if doc.TLSClientCertificateBoundAccessTokens != tc.mtls {
				t.Errorf("tls_client_certificate_bound_access_tokens=%v, want %v", doc.TLSClientCertificateBoundAccessTokens, tc.mtls)
			}
		})
	}
}
