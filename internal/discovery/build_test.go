package discovery_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/discovery"
)

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
