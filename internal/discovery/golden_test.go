package discovery_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/discovery"
	"github.com/libraz/go-oidc-provider/internal/testutil/golden"
)

// TestDiscovery_Golden_AllFeaturesEnabled locks the wire shape of the
// discovery document for a deployment that opts into every optional
// feature. The fixture is the contract RPs build against — incidental
// renames or field reorderings should fail the test rather than ship.
func TestDiscovery_Golden_AllFeaturesEnabled(t *testing.T) {
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
			Introspect: "/introspect",
			Revoke:     "/revoke",
			PAR:        "/par",
		},
		Features: discovery.Features{
			PAR: true, JAR: true, JARM: true, DPoP: true, MTLS: true,
			Introspect: true, Revoke: true,
		},
		GrantsSupported: []string{"authorization_code", "refresh_token"},
		AuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
			"private_key_jwt",
		},
		ScopesSupported: []string{"openid", "profile", "email", "address", "phone", "offline_access"},
	})
	golden.JSON(t, doc, "testdata/discovery_full.golden.json")
}

// TestDiscovery_Golden_MinimalProfile locks the document a deployment
// publishes when only the mandatory endpoints are configured (no PAR / JAR /
// introspect / revoke). The minimal shape is what conformance suites probe
// when they verify a "vanilla" OIDC OP.
func TestDiscovery_Golden_MinimalProfile(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints: discovery.EndpointPaths{
			JWKS:      "/jwks",
			Authorize: "/auth",
			Token:     "/token",
			UserInfo:  "/userinfo",
		},
		GrantsSupported: []string{"authorization_code"},
		ScopesSupported: []string{"openid", "profile", "email", "address", "phone", "offline_access"},
	})
	golden.JSON(t, doc, "testdata/discovery_minimal.golden.json")
}
