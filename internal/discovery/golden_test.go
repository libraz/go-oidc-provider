package discovery_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/discovery"
	"github.com/libraz/go-oidc-provider/internal/testutil/golden"
)

// TestDiscovery_Golden_AllFeaturesEnabled locks the wire shape of the
// discovery document for a deployment that opts into every optional
// feature, including a JWE inventory with a decryption keyset. The
// fixture is the contract RPs build against — incidental renames or
// field reorderings should fail the test rather than ship.
//
// Every [discovery.Features] bit is set and every
// [discovery.EndpointPaths] field is populated, so the fixture is the
// document's upper bound rather than the subset that happened to be
// wired when it was written. That is what makes the newest and most
// drift-prone fields — registration, device authorization, CIBA, grant
// management — part of the contract this test defends; a fixture that
// left their feature bits at their zero value would omit them from the
// golden JSON and notice nothing when they changed.
//
// Two EndpointPaths fields (Interaction, Session) address surfaces the
// OP mounts but does not advertise, so setting them adds no field to
// the document. They are set anyway: this fixture is where "the
// builder does not publish that path" is recorded, and the day one of
// them starts being published the golden diff is the notification.
func TestDiscovery_Golden_AllFeaturesEnabled(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer:      "https://idp.example.com",
		MountPrefix: "/oidc",
		Endpoints: discovery.EndpointPaths{
			JWKS:                "/jwks",
			Authorize:           "/auth",
			Token:               "/token",
			UserInfo:            "/userinfo",
			EndSession:          "/end_session",
			Introspect:          "/introspect",
			Revoke:              "/revoke",
			PAR:                 "/par",
			Interaction:         "/interaction",
			Session:             "/session",
			Register:            "/register",
			DeviceAuthorization: "/device_authorization",
			Backchannel:         "/bc-authorize",
			GrantManagement:     "/grants",
		},
		Features: discovery.Features{
			PAR: true, JAR: true, JARM: true, DPoP: true, MTLS: true,
			Introspect: true, Revoke: true, DynamicRegistration: true,
			AuthorizeEndpoint: true, DeviceCodeGrant: true, CIBAGrant: true,
			EncryptionInbound: true,
		},
		EncryptionAlgsSupported: []string{"RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"},
		EncryptionEncsSupported: []string{"A128GCM", "A256GCM"},
		// The fixture is the maximal document, so it stands for an OP
		// holding a decryption key of every advertised family; the
		// inbound list is the full one for that reason.
		InboundEncryptionAlgsSupported: []string{
			"RSA-OAEP-256", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW",
		},
		RequirePAR: true,
		// The grant list is an input rather than a feature bit, so it
		// has to be widened by hand to stay coherent with the device
		// and CIBA bits above: advertising their endpoints while the
		// grant list omits them is a document no deployment produces.
		GrantsSupported: []string{
			"authorization_code",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:openid:params:grant-type:ciba",
		},
		AuthMethodsSupported: []string{
			"client_secret_basic",
			"client_secret_post",
			"private_key_jwt",
		},
		ScopesSupported:               []string{"openid", "profile", "email", "address", "phone", "offline_access"},
		GrantManagementEnabled:        true,
		GrantManagementActions:        []string{"create", "replace", "merge", "query", "revoke"},
		GrantManagementActionRequired: true,
	})
	golden.JSON(t, doc, "testdata/discovery_full.golden.json")
}

// TestDiscovery_Golden_FullFixtureCarriesEveryOptionalEndpoint asserts
// the maximal fixture publishes every endpoint an optional feature can
// put on the wire.
//
// The golden comparison cannot make this claim by itself. -update
// rewrites the fixture to whatever the builder produced, so a feature
// bit that quietly stopped being set would drop its endpoint from the
// document and from the fixture in the same step, and the comparison
// would go on passing against a smaller contract. Naming the fields is
// what turns their disappearance into a failure.
func TestDiscovery_Golden_FullFixtureCarriesEveryOptionalEndpoint(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("testdata/discovery_full.golden.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	for _, field := range []string{
		"authorization_endpoint",
		"token_endpoint",
		"userinfo_endpoint",
		"jwks_uri",
		"end_session_endpoint",
		"introspection_endpoint",
		"revocation_endpoint",
		"pushed_authorization_request_endpoint",
		"registration_endpoint",
		"device_authorization_endpoint",
		"backchannel_authentication_endpoint",
		"grant_management_endpoint",
	} {
		if value, ok := doc[field].(string); !ok || value == "" {
			t.Errorf("fixture omits %s; the all-features document advertises every optional endpoint", field)
		}
	}
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
		Features:        discovery.Features{AuthorizeEndpoint: true},
		GrantsSupported: []string{"authorization_code"},
		ScopesSupported: []string{"openid", "profile", "email", "address", "phone", "offline_access"},
	})
	golden.JSON(t, doc, "testdata/discovery_minimal.golden.json")
}
