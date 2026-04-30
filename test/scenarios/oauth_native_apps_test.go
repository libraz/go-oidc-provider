package scenarios_test

// Catalog: test/scenarios/catalog/oauth_native_apps.yaml (NA-NNN)
// Spec:
//   - RFC 8252 — OAuth 2.0 for Native Apps
//   - RFC 6749 §3.1.2, §10.6
//   - RFC 3986 — Uniform Resource Identifier
//   - OIDC Dynamic Client Registration §2 (application_type=native)
//   - OpenID Connect RP-Initiated Logout

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

func TestScenario_NA_001_MalformedRedirectURIRejected(t *testing.T) {
	t.Parallel()
	client := &store.Client{
		ID:           "native-na-001",
		RedirectURIs: []string{"http://127.0.0.1/op/callback"},
		Scopes:       []string{"openid"},
		ResponseTypes: []string{
			"code",
		},
		GrantTypes: []string{"authorization_code"},
	}
	for _, raw := range []string{"http:", "http://127.0.0.", "http://127.0.0.1::"} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			values := scenariokit.AuthorizeParams{
				ClientID:    client.ID,
				RedirectURI: raw,
			}.Values()
			req, err := authorize.ParseValues(values)
			if err != nil {
				t.Fatalf("ParseValues(%q): %v", raw, err)
			}
			if err := req.Validate(client, nil, authorize.Policy{
				PKCERequired:         true,
				NonceRequired:        true,
				StateOrNonceRequired: true,
			}); err == nil {
				t.Fatalf("Validate(%q) succeeded, want reject", raw)
			}
		})
	}
}

func TestScenario_NA_002_LocalhostWithRegisteredPortAllowsAnyPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-002")
}

func TestScenario_NA_003_LocalhostWithoutPortAllowsAnyPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-003")
}

func TestScenario_NA_004_IPv4LoopbackWithRegisteredPortAllowsAnyPort(t *testing.T) {
	t.Parallel()
	assertNativeLoopbackAuthorize(t, "http://127.0.0.1:2355/op/callback", "http://127.0.0.1:8888/op/callback")
}

func TestScenario_NA_005_IPv4LoopbackWithoutPortAllowsAnyPort(t *testing.T) {
	t.Parallel()
	assertNativeLoopbackAuthorize(t, "http://127.0.0.1/op/callback", "http://127.0.0.1:8888/op/callback")
}

func TestScenario_NA_006_IPv6LoopbackWithRegisteredPortAllowsAnyPort(t *testing.T) {
	t.Parallel()
	assertNativeLoopbackAuthorize(t, "http://[::1]:2355/op/callback", "http://[::1]:8888/op/callback")
}

func TestScenario_NA_007_IPv6LoopbackWithoutPortAllowsAnyPort(t *testing.T) {
	t.Parallel()
	assertNativeLoopbackAuthorize(t, "http://[::1]/op/callback", "http://[::1]:8888/op/callback")
}

func TestScenario_NA_008_PostLogoutLocalhostWithRegisteredPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-008")
}

func TestScenario_NA_009_PostLogoutLocalhostWithoutPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-009")
}

func TestScenario_NA_010_PostLogoutIPv4WithRegisteredPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-010")
}

func TestScenario_NA_011_PostLogoutIPv4WithoutPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-011")
}

func TestScenario_NA_012_PostLogoutIPv6WithRegisteredPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-012")
}

func TestScenario_NA_013_PostLogoutIPv6WithoutPort(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-013")
}

func TestScenario_NA_014_RegistrationRejectsNonLoopbackHTTPRedirect(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-014")
}

func TestScenario_NA_015_RegistrationRejectsNonLoopbackHTTPPostLogout(t *testing.T) {
	t.Parallel()
	t.Skip("pending: NA-015")
}

func assertNativeLoopbackAuthorize(t *testing.T, registered, requested string) {
	t.Helper()

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:           "native-loopback",
		RedirectURIs: []string{registered},
		PublicClient: true,
		Scopes:       []string{"openid", "profile", "email"},
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: requested,
		PKCE:        pkce,
	})
	if flow.Error != "" {
		t.Fatalf("authorize error=%s desc=%s", flow.Error, flow.ErrorDesc)
	}
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	if got := flow.Location.String(); got == "" || flow.Location.Host == "" {
		t.Fatalf("callback location malformed: %v", flow.Location)
	}
}
