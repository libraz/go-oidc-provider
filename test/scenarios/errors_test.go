package scenarios_test

// Catalog: test/scenarios/catalog/errors.yaml (ERR-NNN)
// Spec:
//   - RFC 6749 §5.2 — Error Response
//   - RFC 7807 — Problem Details (informational)
//   - OIDC Core 1.0 §3.1.2.6 — Authentication Error Response
//   - OIDC Core 1.0 §16.5 — Native Apps / non-redirect errors
//   - RFC 7235 — HTTP Authentication (WWW-Authenticate)
//   - RFC 9207 — iss parameter on errors
//   - RFC 6750 §3 — Bearer authentication challenge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// postTokenErrorJSON drives a deliberately malformed /token request
// against tk so the OP returns a JSON RFC 6749 §5.2 error envelope.
// The grant_type is omitted, so the dispatcher rejects with
// invalid_request before any client authentication runs. The test
// caller controls the request's Accept header, which is the
// content-negotiation surface ERR-001 / ERR-002 / ERR-003 exercise.
func postTokenErrorJSON(tb testing.TB, tk *testkit.Provider, accept string) (*http.Response, []byte) {
	tb.Helper()
	body := strings.NewReader("foo=bar")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", body)
	if err != nil {
		tb.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		tb.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("read /token body: %v", err)
	}
	return resp, raw
}

// TestScenario_ERR_001_NoAcceptHeaderProducesJSON verifies that a
// /token request with no Accept header still receives an
// application/json error envelope. The token endpoint is wire-
// machine-readable; never an HTML page.
//
// Spec: RFC 6749 §5.2.
func TestScenario_ERR_001_NoAcceptHeaderProducesJSON(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)

	resp, body := postTokenErrorJSON(t, tk, "")
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("status=%d want 4xx error", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.Contains(got, "json") {
		t.Errorf("Content-Type=%q want a json media type", got)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if env["error"] == nil {
		t.Errorf("body missing error field: %s", string(body))
	}
}

// TestScenario_ERR_002_AcceptStarSlashStarProducesJSON verifies that
// a /token request with `Accept: */*` (the typical curl / fetch
// default) receives JSON, never HTML. The token endpoint MUST stay
// machine-readable regardless of the broad Accept value.
//
// Spec: RFC 6749 §5.2.
func TestScenario_ERR_002_AcceptStarSlashStarProducesJSON(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)

	resp, body := postTokenErrorJSON(t, tk, "*/*")
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("status=%d want 4xx error", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.Contains(got, "json") {
		t.Errorf("Content-Type=%q want a json media type", got)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if env["error"] == nil {
		t.Errorf("body missing error field: %s", string(body))
	}
}

func TestScenario_ERR_003_BrowserAcceptProducesHTML(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-003")
}

// TestScenario_ERR_010_JSONErrorBodyHasErrorCode verifies that the
// JSON error envelope carries `error` (one of the registered RFC 6749
// codes) and that `error_description`, when present, is a single
// printable ASCII line.
//
// Spec: RFC 6749 §5.2.
func TestScenario_ERR_010_JSONErrorBodyHasErrorCode(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)

	_, body := postTokenErrorJSON(t, tk, "application/json")
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	code, _ := env["error"].(string)
	if code == "" {
		t.Fatalf("error field empty or missing: %s", string(body))
	}
	registered := map[string]struct{}{
		"invalid_request":            {},
		"invalid_client":             {},
		"invalid_grant":              {},
		"unauthorized_client":        {},
		"unsupported_grant_type":     {},
		"invalid_scope":              {},
		"invalid_target":             {},
		"invalid_dpop_proof":         {},
		"unsupported_token_type":     {},
		"invalid_token":              {},
		"server_error":               {},
		"temporarily_unavailable":    {},
		"access_denied":              {},
		"interaction_required":       {},
		"login_required":             {},
		"consent_required":           {},
		"account_selection_required": {},
	}
	if _, ok := registered[code]; !ok {
		t.Errorf("error=%q is not a registered OAuth/OIDC error code", code)
	}
	if descRaw, present := env["error_description"]; present {
		desc, ok := descRaw.(string)
		if !ok {
			t.Fatalf("error_description is %T, want string", descRaw)
		}
		if strings.ContainsAny(desc, "\r\n") {
			t.Errorf("error_description contains a newline (RFC 6749 §5.2 requires a single line): %q", desc)
		}
		for _, r := range desc {
			if r < 0x20 || r > 0x7e {
				t.Errorf("error_description contains non-printable-ASCII rune %q in %q", r, desc)
				break
			}
		}
	}
}

func TestScenario_ERR_011_ErrorURIOmittedByDefault(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-011")
}

// TestScenario_ERR_012_JSONErrorOmitsState verifies that a JSON error
// response from /token never includes a `state` field. RFC 6749
// reserves `state` for redirect-style responses (§4.1.2.1), where the
// AS echoes the value the RP sent at /authorize. JSON endpoints have
// no opaque-redirect channel for `state`; emitting it here would be a
// reflection vector and a spec violation.
//
// Spec: OIDC Core §3.1.2.6 / RFC 6749 §5.2.
func TestScenario_ERR_012_JSONErrorOmitsState(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)

	_, body := postTokenErrorJSON(t, tk, "application/json")
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if _, present := env["state"]; present {
		t.Errorf("JSON error body MUST NOT include state: %s", string(body))
	}
}

// TestScenario_ERR_020_BearerEndpointEmitsWWWAuthenticate verifies
// that /userinfo responds to a malformed Bearer token with 401 and a
// `WWW-Authenticate: Bearer ...` challenge that names the error code.
// RFC 6750 §3 binds this header to every protected-resource 401 so
// HTTP-aware Bearer clients can resolve the failure mode.
//
// Spec: RFC 6750 §3.
func TestScenario_ERR_020_BearerEndpointEmitsWWWAuthenticate(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)

	_, _, doc := fetchDiscovery(t, tk.Server.URL)
	userinfo, _ := doc["userinfo_endpoint"].(string)
	if userinfo == "" {
		t.Fatalf("discovery doc missing userinfo_endpoint")
	}
	// Rewrite the issuer-prefixed URL onto the httptest base so the
	// request lands on the in-process server.
	if strings.HasPrefix(userinfo, "https://") {
		if slash := strings.Index(userinfo[len("https://"):], "/"); slash >= 0 {
			userinfo = tk.Server.URL + userinfo[len("https://")+slash:]
		}
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, userinfo, http.NoBody)
	if err != nil {
		t.Fatalf("build /userinfo request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	hdr := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(strings.ToLower(hdr), "bearer") {
		t.Errorf("WWW-Authenticate=%q must begin with Bearer", hdr)
	}
	if !strings.Contains(hdr, "invalid_token") {
		t.Errorf("WWW-Authenticate=%q must declare error=invalid_token", hdr)
	}
}

// TestScenario_ERR_021_BasicAuthFailureEmitsWWWAuthenticate verifies
// that a /token request authenticated with HTTP Basic but bad
// credentials returns 401 with `WWW-Authenticate: Basic realm="..."`.
// RFC 6749 §5.2 inherits the Basic-auth challenge requirement from
// RFC 7617; without the header, RP libraries that follow the
// Basic-auth state machine cannot retry intelligently.
//
// Spec: RFC 6749 §5.2 / RFC 7617.
func TestScenario_ERR_021_BasicAuthFailureEmitsWWWAuthenticate(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)

	form := strings.NewReader("grant_type=client_credentials")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", form)
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("ghost-client", "wrong-secret")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	hdr := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(strings.ToLower(hdr), "basic") {
		t.Errorf("WWW-Authenticate=%q must begin with Basic", hdr)
	}
	if !strings.Contains(strings.ToLower(hdr), "realm=") {
		t.Errorf("WWW-Authenticate=%q must include realm parameter", hdr)
	}
}

func TestScenario_ERR_022_CORSExposesWWWAuthenticate(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-022")
}

func TestScenario_ERR_030_HTMLErrorPathReachableViaHook(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-030")
}

func TestScenario_ERR_031_ErrorPageHTMLEscapesValues(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-031")
}

func TestScenario_ERR_032_ErrorCatalogIsSingleSourceOfTruth(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-032")
}

func TestScenario_ERR_040_UncaughtExceptionsBecomeServerError(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ERR-040")
}

// TestScenario_ERR_050_AuthorizationErrorRedirectIncludesIss
// verifies that an authorize-endpoint error redirect carries
// `iss=<issuer>` per RFC 9207. The trigger is a scope outside the
// client's registered set, which is rejected after redirect_uri has
// been validated, so the OP redirects back with `error=invalid_scope`
// AND `iss`. The same behaviour is asserted from the issuer-
// identification angle in TestScenario_ISS_020_*; the duplicate
// binding catches regressions from the errors-feature side.
//
// Spec: RFC 9207 §2.
func TestScenario_ERR_050_AuthorizationErrorRedirectIncludesIss(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-err-050"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-err-050-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid not_registered",
		PKCE:        scenariokit.NewPKCEPair(""),
	})
	if flow.Error == "" {
		t.Fatalf("expected an error redirect, got code=%q", flow.Code)
	}
	if flow.Iss == "" {
		t.Fatal("authorization error redirect missing iss query parameter")
	}
	if flow.Iss != tk.Issuer {
		t.Errorf("iss=%q want %q", flow.Iss, tk.Issuer)
	}
}
