package discovery_test

import (
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/discovery"
)

// TestValidateIssuer enforces the OIDC Discovery 1.0 §3 / FAPI 2.0
// §5.4 shape constraints on the issuer URL. The matrix fixes the
// allowed shapes (https, no trailing slash, no query / fragment) and
// the loopback-only carve-out for the http scheme (development boots
// with a plain-text issuer must still surface as a misconfiguration
// in production). Each row drives a single ValidateIssuer call.
func TestValidateIssuer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		issuer  string
		wantErr bool
	}{
		{"empty", "", true},
		{"plain-https", "https://idp.example.com", false},
		{"https-with-port", "https://idp.example.com:8443", false},
		{"https-with-path", "https://idp.example.com/oidc", false},
		{"trailing-slash", "https://idp.example.com/", true},
		{"trailing-slash-with-path", "https://idp.example.com/oidc/", true},
		{"with-query", "https://idp.example.com/?foo=bar", true},
		{"with-fragment", "https://idp.example.com/#x", true},
		{"http-public", "http://idp.example.com", true},
		{"http-localhost", "http://localhost:8080", true},
		{"http-loopback-v4", "http://127.0.0.1:8080", false},
		{"http-loopback-v4-secondary", "http://127.0.0.2:8080", false},
		{"http-loopback-v6", "http://[::1]:8080", false},
		{"http-private-ip", "http://10.0.0.1", true},
		{"unknown-scheme", "ftp://idp.example.com", true},
		{"relative", "/oidc", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := discovery.ValidateIssuer(tc.issuer)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ValidateIssuer(%q) = nil, want error", tc.issuer)
				}
				if !errors.Is(err, discovery.ErrIssuerInvalid) {
					t.Errorf("ValidateIssuer(%q) error = %v, want errors.Is ErrIssuerInvalid", tc.issuer, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateIssuer(%q) unexpected error: %v", tc.issuer, err)
			}
		})
	}
}

func TestBuild_FormsAbsoluteURLs(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints: discovery.EndpointPaths{
			JWKS:       "/jwks",
			Authorize:  "/auth",
			Token:      "/token",
			UserInfo:   "/userinfo",
			EndSession: "/end_session",
		},
		GrantsSupported: []string{"authorization_code", "refresh_token"},
	})

	cases := map[string]string{
		doc.Issuer:                "https://idp.example.com",
		doc.AuthorizationEndpoint: "https://idp.example.com/oidc/auth",
		doc.TokenEndpoint:         "https://idp.example.com/oidc/token",
		doc.UserInfoEndpoint:      "https://idp.example.com/oidc/userinfo",
		doc.JWKSURI:               "https://idp.example.com/oidc/jwks",
		doc.EndSessionEndpoint:    "https://idp.example.com/oidc/end_session",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("got %q want %q", got, want)
		}
	}
}

func TestBuild_RootMountPrefix(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/",
		Endpoints: discovery.EndpointPaths{
			JWKS:      "/jwks",
			Authorize: "/auth",
			Token:     "/token",
		},
	})
	if got := doc.AuthorizationEndpoint; got != "https://idp.example.com/auth" {
		t.Errorf("authorization_endpoint=%q", got)
	}
	if got := doc.JWKSURI; got != "https://idp.example.com/jwks" {
		t.Errorf("jwks_uri=%q", got)
	}
}

func TestBuild_OmitsDisabledFeatureEndpoints(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints: discovery.EndpointPaths{
			JWKS:       "/jwks",
			Authorize:  "/auth",
			Token:      "/token",
			Introspect: "/introspect",
			Revoke:     "/revoke",
			PAR:        "/par",
		},
		Features: discovery.Features{}, // all disabled
	})
	if doc.IntrospectionEndpoint != "" {
		t.Error("introspection endpoint must be omitted when feature disabled")
	}
	if doc.RevocationEndpoint != "" {
		t.Error("revocation endpoint must be omitted when feature disabled")
	}
	if doc.PushedAuthorizationRequestEndpoint != "" {
		t.Error("PAR endpoint must be omitted when feature disabled")
	}
	if doc.RequestParameterSupported || doc.RequestURIParameterSupported {
		t.Error("JAR parameters must be false when feature disabled")
	}
}

func TestBuild_EmitsEndpointsWhenFeaturesEnabled(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints: discovery.EndpointPaths{
			JWKS:       "/jwks",
			Authorize:  "/auth",
			Token:      "/token",
			Introspect: "/introspect",
			Revoke:     "/revoke",
			PAR:        "/par",
		},
		Features: discovery.Features{
			PAR: true, JAR: true, Introspect: true, Revoke: true,
		},
	})
	if got := doc.IntrospectionEndpoint; got != "https://idp.example.com/oidc/introspect" {
		t.Errorf("introspection_endpoint=%q", got)
	}
	if got := doc.RevocationEndpoint; got != "https://idp.example.com/oidc/revoke" {
		t.Errorf("revocation_endpoint=%q", got)
	}
	if got := doc.PushedAuthorizationRequestEndpoint; got != "https://idp.example.com/oidc/par" {
		t.Errorf("par_endpoint=%q", got)
	}
	if !doc.RequestParameterSupported || !doc.RequestURIParameterSupported {
		t.Error("JAR parameters must be true when feature enabled")
	}
}

func TestBuild_StaticPolicyValues(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints:   discovery.EndpointPaths{JWKS: "/jwks", Authorize: "/auth", Token: "/token"},
	})
	if len(doc.ResponseTypesSupported) != 1 || doc.ResponseTypesSupported[0] != "code" {
		t.Errorf("response_types_supported=%v want [code]", doc.ResponseTypesSupported)
	}
	if len(doc.IDTokenSigningAlgValuesSupported) != 1 || doc.IDTokenSigningAlgValuesSupported[0] != "ES256" {
		t.Errorf("id_token_signing_alg=%v want [ES256]", doc.IDTokenSigningAlgValuesSupported)
	}
	if len(doc.CodeChallengeMethodsSupported) != 1 || doc.CodeChallengeMethodsSupported[0] != "S256" {
		t.Errorf("code_challenge_methods=%v want [S256]", doc.CodeChallengeMethodsSupported)
	}
}

func TestBuild_ProfileFiltersTokenAuthMethods(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints: discovery.EndpointPaths{
			JWKS: "/jwks", Authorize: "/auth", Token: "/token",
			Introspect: "/introspect", Revoke: "/revoke",
		},
		Features: discovery.Features{MTLS: true, Introspect: true, Revoke: true},
		// FAPI 2.0 §3.1.3 narrowing: secret_basic and secret_post must
		// not appear even though MTLS is enabled (which would otherwise
		// add tls_client_auth on top of the default secret list).
		ProfileAllowedAuthMethods: []string{
			"private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth",
		},
	})
	for _, banned := range []string{"client_secret_basic", "client_secret_post", "none"} {
		for _, got := range doc.TokenEndpointAuthMethodsSupported {
			if got == banned {
				t.Errorf("token_endpoint_auth_methods_supported still contains %q", banned)
			}
		}
	}
	for _, want := range []string{"tls_client_auth", "self_signed_tls_client_auth"} {
		found := false
		for _, got := range doc.TokenEndpointAuthMethodsSupported {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("token_endpoint_auth_methods_supported missing %q (got %v)",
				want, doc.TokenEndpointAuthMethodsSupported)
		}
	}
	// Introspection / revocation lists mirror the filtered token list,
	// so the same bans must apply there too.
	for _, got := range doc.IntrospectionEndpointAuthMethodsSupported {
		if got == "client_secret_basic" {
			t.Errorf("introspection_endpoint_auth_methods_supported still contains client_secret_basic")
		}
	}
	for _, got := range doc.RevocationEndpointAuthMethodsSupported {
		if got == "client_secret_basic" {
			t.Errorf("revocation_endpoint_auth_methods_supported still contains client_secret_basic")
		}
	}
}

func TestBuild_NoProfileLeavesAuthMethodsAlone(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints:   discovery.EndpointPaths{JWKS: "/jwks", Authorize: "/auth", Token: "/token"},
	})
	// Default list is the secret pair when nothing else is configured;
	// passing a nil ProfileAllowedAuthMethods MUST NOT strip them.
	hasBasic := false
	for _, m := range doc.TokenEndpointAuthMethodsSupported {
		if m == "client_secret_basic" {
			hasBasic = true
			break
		}
	}
	if !hasBasic {
		t.Errorf("token_endpoint_auth_methods_supported = %v, want it to retain client_secret_basic when no profile is set",
			doc.TokenEndpointAuthMethodsSupported)
	}
}

func TestBuild_ClaimsSupported_OmittedByDefault(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints:   discovery.EndpointPaths{JWKS: "/jwks", Authorize: "/auth", Token: "/token"},
	})
	if doc.ClaimsSupported != nil {
		t.Errorf("claims_supported = %v, want nil when WithClaimsSupported is not configured", doc.ClaimsSupported)
	}
}

func TestBuild_ClaimsSupported_PreservesEmbedderList(t *testing.T) {
	t.Parallel()

	want := []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email"}
	doc := discovery.Build(discovery.Input{
		Issuer:          "https://idp.example.com",
		MountPrefix:     "/oidc",
		Endpoints:       discovery.EndpointPaths{JWKS: "/jwks", Authorize: "/auth", Token: "/token"},
		ClaimsSupported: want,
	})
	if len(doc.ClaimsSupported) != len(want) {
		t.Fatalf("claims_supported len=%d want %d (%v)", len(doc.ClaimsSupported), len(want), doc.ClaimsSupported)
	}
	for i, c := range want {
		if doc.ClaimsSupported[i] != c {
			t.Errorf("claims_supported[%d]=%q want %q", i, doc.ClaimsSupported[i], c)
		}
	}
}

func TestBuild_ClaimsSupported_EmptySlicePreserved(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:          "https://idp.example.com",
		MountPrefix:     "/oidc",
		Endpoints:       discovery.EndpointPaths{JWKS: "/jwks", Authorize: "/auth", Token: "/token"},
		ClaimsSupported: []string{},
	})
	if doc.ClaimsSupported == nil {
		t.Errorf("claims_supported = nil, want empty non-nil slice (embedder explicitly opted in with empty list)")
	}
	if len(doc.ClaimsSupported) != 0 {
		t.Errorf("claims_supported = %v, want empty slice", doc.ClaimsSupported)
	}
}
