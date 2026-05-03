package scenarios_test

// Catalog: test/scenarios/catalog/client_credentials.yaml (CC-NNN)
// Spec:
//   - RFC 6749 §4.4 — Client Credentials Grant
//   - RFC 6749 §3.3 — Access Token Scope
//   - RFC 6749 §5.1 / §5.2 — Token Response & Error Format
//   - RFC 6750 — Bearer Token Usage

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestScenario_CC_001_ConfidentialClientGetsAccessToken pins the
// happy path of the client_credentials grant. A confidential client
// authenticates with client_secret_basic and POSTs
// grant_type=client_credentials with an in-set scope. The OP MUST
// reply 200 with a JSON envelope carrying access_token, expires_in,
// token_type, and scope. The body MUST NOT include refresh_token or
// id_token because the cc grant has no end-user resource owner (RFC
// 6749 §4.4.3 forbids the former and there is no subject for the
// latter). token_type is "Bearer" on the bearer-default path.
//
// Spec: RFC 6749 §4.4.3, §5.1.
func TestScenario_CC_001_ConfidentialClientGetsAccessToken(t *testing.T) {
	t.Parallel()

	const clientID = "rp-cc-001"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-cc-001-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		Scopes:                  []string{"api"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"client_credentials"},
	})

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"api"},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, string(body))
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}

	if at, _ := env["access_token"].(string); at == "" {
		t.Errorf("access_token missing/empty: %v", env)
	}
	if got, _ := env["token_type"].(string); got != "Bearer" {
		t.Errorf("token_type=%v want Bearer", env["token_type"])
	}
	if got, ok := env["expires_in"].(float64); !ok || got <= 0 {
		t.Errorf("expires_in=%v want positive number", env["expires_in"])
	}
	if got, _ := env["scope"].(string); got != "api" {
		t.Errorf("scope=%q want %q", got, "api")
	}

	// RFC 6749 §4.4.3: no refresh_token. No id_token because the cc
	// grant has no resource owner.
	if got, present := env["refresh_token"]; present {
		t.Errorf("refresh_token must NOT be issued on cc grant; got %v", got)
	}
	if got, present := env["id_token"]; present {
		t.Errorf("id_token must NOT be issued on cc grant; got %v", got)
	}
}

// TestScenario_CC_002_UnsupportedScopeNarrowedSilently is OOS — see catalog out_of_scope_reason.
func TestScenario_CC_002_UnsupportedScopeNarrowedSilently(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CC-002 (see catalog out_of_scope_reason)")
}

// TestScenario_CC_003_DisallowedScopeRejected pins the negative path
// of the client_credentials scope policy. v1.0 rejects rather than
// silently narrowing when the requested scope contains a value
// outside the client's registered Scopes set
// (internal/grants/clientcred/clientcred.go ErrScopeForbidden). The
// wire response MUST be 400 with error=invalid_scope and an
// error_description that v1.0 emits as "requested scope exceeds the
// client's registered set" (internal/tokenendpoint/clientcred.go
// writeClientCredsAuthError). The response MUST NOT include any
// success-side keys (access_token / token_type).
//
// Spec: RFC 6749 §3.3 / §5.2.
func TestScenario_CC_003_DisallowedScopeRejected(t *testing.T) {
	t.Parallel()

	const clientID = "rp-cc-003"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-cc-003-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		Scopes:                  []string{"api"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"client_credentials"},
	})

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"api forbidden"},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, string(body))
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if got, _ := env["error"].(string); got != "invalid_scope" {
		t.Errorf("error=%q want invalid_scope (raw=%s)", got, string(body))
	}
	desc, _ := env["error_description"].(string)
	if !strings.Contains(desc, "scope") {
		t.Errorf("error_description=%q must mention scope", desc)
	}
	if _, present := env["access_token"]; present {
		t.Errorf("rejection must not mint access_token: %v", env)
	}
	if _, present := env["token_type"]; present {
		t.Errorf("rejection must not include token_type: %v", env)
	}
}

// TestScenario_CC_004_EntitiesOmitAccountAndGrant is OOS — see catalog out_of_scope_reason.
func TestScenario_CC_004_EntitiesOmitAccountAndGrant(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CC-004 (see catalog out_of_scope_reason)")
}
