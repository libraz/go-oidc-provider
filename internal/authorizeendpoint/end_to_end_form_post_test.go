package authorizeendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestEndToEnd_FormPost_Success drives the full /authorize → /interaction
// happy path with response_mode=form_post and asserts the OP returns the
// OIDC Core Form Post Response Mode 1.0 body shape: HTTP 200, HTML
// content type, strict CSP, and one hidden input per response parameter
// (code, state, iss). The OFCS module
// "oidcc-formpost-basic-certification-test-plan/oidcc-formpost-basic-server"
// pins the same shape.
func TestEndToEnd_FormPost_Success(t *testing.T) {
	t.Parallel()

	tk, rp, secret := newFormPostHarness(t)
	resp := drivePostInteraction(t, tk, rp, secret, "form_post", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, string(dump))
	}
	if got := resp.Header.Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type=%q", got)
	}
	if csp := resp.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP missing strict default-src: %q", csp)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, `action="`+rp.RedirectURIs[0]+`"`) {
		t.Errorf("body missing form action %q: %s", rp.RedirectURIs[0], bodyStr)
	}
	if code := extractFormPostField(t, bodyStr, "code"); code == "" {
		t.Errorf("code field missing or empty in form body: %s", bodyStr)
	}
	if got := extractFormPostField(t, bodyStr, "state"); got != "state-abc" {
		t.Errorf("state=%q want state-abc", got)
	}
	if got := extractFormPostField(t, bodyStr, "iss"); got == "" {
		t.Errorf("iss field missing (RFC 9207 §2.3): %s", bodyStr)
	}
}

// TestEndToEnd_FormPost_Error pins the symmetric error path: when the
// client sends response_mode=form_post and the request fails post-redirect
// validation, the OP returns the error envelope through the same form_post
// body (rather than the legacy ?error=... redirect). RFC 9207 §2.4
// requires "iss" on error responses too.
func TestEndToEnd_FormPost_Error(t *testing.T) {
	t.Parallel()

	tk, rp, _ := newFormPostHarness(t)

	// Drive an unrecoverable post-redirect error: an unsupported scope
	// reaches the OP after the redirect_uri has already been validated,
	// so the error is delivered via the requested response_mode.
	values := e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0])
	values.Set("response_mode", "form_post")
	values.Set("scope", "openid offline_access wholly_unknown_scope_xyz")
	authorizeURL := tk.Server.URL + "/oidc/auth?" + values.Encode()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := tk.HTTPClient(jar)
	resp, err := newGet(authorizeURL).Do(client)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s (want 200 form_post body)", resp.StatusCode, string(dump))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	bodyStr := string(body)
	if got := extractFormPostField(t, bodyStr, "error"); got == "" {
		t.Errorf("error field missing: %s", bodyStr)
	}
	if got := extractFormPostField(t, bodyStr, "iss"); got == "" {
		t.Errorf("iss field missing on error path (RFC 9207 §2.4): %s", bodyStr)
	}
}

func newFormPostHarness(t *testing.T) (*testkit.Provider, *store.Client, string) {
	t.Helper()

	clock := fakeClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t, testkit.WithClock(clock))
	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-form-post",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	return tk, rp, secret
}

// drivePostInteraction walks /authorize → /interaction → terminal POST
// the same way [TestEndToEnd_AuthorizeInteractionToken_HappyPath] does,
// returning the response from the terminal interaction POST. mode is
// the response_mode parameter; extraScope is appended to the canonical
// "openid profile email" scope when non-empty.
func drivePostInteraction(t *testing.T, tk *testkit.Provider, rp *store.Client, _, mode, extraScope string) *http.Response {
	t.Helper()

	values := e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0])
	if mode != "" {
		values.Set("response_mode", mode)
	}
	if extraScope != "" {
		values.Set("scope", values.Get("scope")+" "+extraScope)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := tk.HTTPClient(jar)

	authResp, err := newGet(tk.Server.URL + "/oidc/auth?" + values.Encode()).Do(client)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(authResp.Body)
		t.Fatalf("authorize status=%d body=%s", authResp.StatusCode, string(dump))
	}
	location, err := authResp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	stepResp, err := newGet(tk.Server.URL + location.Path).Do(client)
	if err != nil {
		t.Fatalf("GET interaction: %v", err)
	}
	defer stepResp.Body.Close()
	step := decodeMap(t, stepResp)
	stateRef, _ := step["state_ref"].(string)
	if stateRef == "" {
		t.Fatal("state_ref missing from step body")
	}
	csrfCookie := findCookie(stepResp.Cookies(), "__Host-oidc_csrf")
	if csrfCookie == nil {
		t.Fatal("csrf cookie missing")
	}
	body := map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{"subject": "user-1"},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+location.Path, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest POST: %v", err)
	}
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Origin", tk.Issuer)
	postReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	postReq.AddCookie(csrfCookie)
	postResp, err := client.Do(postReq)
	if err != nil {
		t.Fatalf("POST interaction: %v", err)
	}
	return completeConsentIfPrompted(t, client, tk.Server.URL+location.Path, tk.Issuer, csrfCookie.Value, postResp)
}

// extractFormPostField returns the value attribute of the
// `<input type="hidden" name="<field>" value="...">` element in the OIDC
// Core form_post body. The body shape is fixed by
// [jarm.WriteParamsFormPost], so we substring-match rather than HTML-
// parse to keep the helper self-contained. An absent field returns "".
func extractFormPostField(t *testing.T, body, field string) string {
	t.Helper()

	startTag := `name="` + field + `" value="`
	idx := strings.Index(body, startTag)
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(startTag):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		t.Fatalf("malformed hidden input for %q in body: %s", field, body)
	}
	// Decode HTML entities the writer escaped (e.g. & → &amp;). The
	// authorization values used in tests do not need full entity
	// decoding so a minimal mapper covers state / iss / code.
	return strings.NewReplacer("&amp;", "&").Replace(rest[:end])
}
