package scenarios_test

// Catalog: test/scenarios/catalog/oauth_native_apps.yaml (NA-NNN)
// Spec:
//   - RFC 8252 — OAuth 2.0 for Native Apps
//   - RFC 6749 §3.1.2, §10.6
//   - RFC 3986 — Uniform Resource Identifier
//   - OIDC Dynamic Client Registration §2 (application_type=native)
//   - OpenID Connect RP-Initiated Logout

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/op"
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

// TestScenario_NA_002_LocalhostWithRegisteredPortAllowsAnyPort pins
// the textual-localhost arm of the native-app loopback wildcard. RFC
// 8252 §7.3 admits 127.0.0.1, [::1], and the textual "localhost" for
// native clients; DCR honours all three at registration so the
// authorize-side wildcard MUST mirror the same set.
func TestScenario_NA_002_LocalhostWithRegisteredPortAllowsAnyPort(t *testing.T) {
	t.Parallel()
	assertNativeLoopbackAuthorize(t, "http://localhost:2355/op/callback", "http://localhost:8888/op/callback")
}

// TestScenario_NA_003_LocalhostWithoutPortAllowsAnyPort exercises the
// no-port-registered variant of NA-002: a client that registers
// http://localhost/op/callback can dial back on any ephemeral port.
func TestScenario_NA_003_LocalhostWithoutPortAllowsAnyPort(t *testing.T) {
	t.Parallel()
	assertNativeLoopbackAuthorize(t, "http://localhost/op/callback", "http://localhost:8888/op/callback")
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

// TestScenario_NA_008_PostLogoutLocalhostWithRegisteredPort is OOS — see catalog out_of_scope_reason.
func TestScenario_NA_008_PostLogoutLocalhostWithRegisteredPort(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: NA-008 (see catalog out_of_scope_reason)")
}

// TestScenario_NA_009_PostLogoutLocalhostWithoutPort is OOS — see catalog out_of_scope_reason.
func TestScenario_NA_009_PostLogoutLocalhostWithoutPort(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: NA-009 (see catalog out_of_scope_reason)")
}

// TestScenario_NA_010_PostLogoutIPv4WithRegisteredPort is OOS — see catalog out_of_scope_reason.
func TestScenario_NA_010_PostLogoutIPv4WithRegisteredPort(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: NA-010 (see catalog out_of_scope_reason)")
}

// TestScenario_NA_011_PostLogoutIPv4WithoutPort is OOS — see catalog out_of_scope_reason.
func TestScenario_NA_011_PostLogoutIPv4WithoutPort(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: NA-011 (see catalog out_of_scope_reason)")
}

// TestScenario_NA_012_PostLogoutIPv6WithRegisteredPort is OOS — see catalog out_of_scope_reason.
func TestScenario_NA_012_PostLogoutIPv6WithRegisteredPort(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: NA-012 (see catalog out_of_scope_reason)")
}

// TestScenario_NA_013_PostLogoutIPv6WithoutPort is OOS — see catalog out_of_scope_reason.
func TestScenario_NA_013_PostLogoutIPv6WithoutPort(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: NA-013 (see catalog out_of_scope_reason)")
}

// TestScenario_NA_014_RegistrationRejectsNonLoopbackHTTPRedirect drives
// the public /oidc/register endpoint with application_type=native and a
// redirect_uri that uses plain http to a non-loopback host. RFC 8252
// §7.3 (and §8.3) forbids the carve-out for non-loopback hosts; the OP
// MUST reject the registration with 400 invalid_redirect_uri and the
// error_description MUST name the loopback constraint so an embedder
// reading the response can self-correct.
//
// Spec: RFC 8252 §7.3 / §8.3, OIDC Dynamic Client Registration §2.
func TestScenario_NA_014_RegistrationRejectsNonLoopbackHTTPRedirect(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	issued, err := tk.OP.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{})
	if err != nil {
		t.Fatalf("IssueInitialAccessToken: %v", err)
	}

	body, err := json.Marshal(map[string]any{
		"application_type": "native",
		"redirect_uris":    []string{"http://rp.example.com/op/callback"},
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/register", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+issued.Value)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /oidc/register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	raw, _ := io.ReadAll(resp.Body)
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(raw))
	}
	if got, _ := env["error"].(string); got != "invalid_redirect_uri" {
		t.Errorf("error=%q want invalid_redirect_uri (raw=%s)", got, string(raw))
	}
	desc, _ := env["error_description"].(string)
	if !strings.Contains(desc, "loopback") {
		t.Errorf("error_description=%q must name the loopback carve-out", desc)
	}
}

// TestScenario_NA_015_RegistrationRejectsNonLoopbackHTTPPostLogout drives
// the public /oidc/register endpoint with a loopback http redirect_uri
// (so the OP infers native from the redirect_uri shape per RFC 8252
// §7.3) and a non-loopback http post_logout_redirect_uri. OIDC
// RP-Initiated Logout 1.0 §3 inherits the native loopback constraint;
// the OP MUST reject the registration with 400 invalid_client_metadata
// and the error_description MUST name both the offending field and the
// loopback carve-out so an embedder reading the response can
// self-correct.
//
// Spec: RFC 8252 §7.3, OIDC RP-Initiated Logout 1.0 §3.
func TestScenario_NA_015_RegistrationRejectsNonLoopbackHTTPPostLogout(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	issued, err := tk.OP.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{})
	if err != nil {
		t.Fatalf("IssueInitialAccessToken: %v", err)
	}

	body, err := json.Marshal(map[string]any{
		"redirect_uris":             []string{"http://127.0.0.1/op/callback"},
		"post_logout_redirect_uris": []string{"http://rp.example.com/op/logout"},
	})
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/register", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+issued.Value)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /oidc/register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	raw, _ := io.ReadAll(resp.Body)
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(raw))
	}
	if got, _ := env["error"].(string); got != "invalid_client_metadata" {
		t.Errorf("error=%q want invalid_client_metadata (raw=%s)", got, string(raw))
	}
	desc, _ := env["error_description"].(string)
	if !strings.Contains(desc, "post_logout_redirect_uris") {
		t.Errorf("error_description=%q must name the post_logout_redirect_uris field", desc)
	}
	if !strings.Contains(desc, "loopback") {
		t.Errorf("error_description=%q must name the loopback carve-out", desc)
	}
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
