package authorizeendpoint_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// e2eVerifier is the canonical PKCE verifier reused across the end-to-end
// tests. It comfortably satisfies the 43..128 RFC 7636 §4.1 bound.
const e2eVerifier = "test-verifier-test-verifier-test-verifier-test-verifier-1234567"

// e2eChallenge derives the SHA-256 base64url challenge from [e2eVerifier].
func e2eChallenge() string {
	sum := sha256.Sum256([]byte(e2eVerifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// TestEndToEnd_AuthorizeInteractionToken_HappyPath drives the full
// /authorize → /interaction → /token flow against a real testkit-backed
// server. The shape of the test mirrors what the conformance harness
// runs for "oidcc-basic-op".
func TestEndToEnd_AuthorizeInteractionToken_HappyPath(t *testing.T) {
	t.Parallel()

	clock := fakeClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t, testkit.WithClock(clock))
	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-1",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := tk.HTTPClient(jar)

	authorizeURL := tk.Server.URL + "/oidc/auth?" + e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0]).Encode()
	authResp, err := newGet(authorizeURL).Do(client)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status=%d", authResp.StatusCode)
	}
	location, err := authResp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if !strings.HasPrefix(location.Path, "/oidc/interaction/") {
		t.Fatalf("Location=%s", location.String())
	}

	// 2: GET /interaction/{uid} → fetch CSRF token.
	stepResp, err := newGet(tk.Server.URL + location.Path).Do(client)
	if err != nil {
		t.Fatalf("GET interaction: %v", err)
	}
	defer stepResp.Body.Close()
	if stepResp.StatusCode != http.StatusOK {
		t.Fatalf("interaction GET status=%d", stepResp.StatusCode)
	}
	step := decodeMap(t, stepResp)
	stateRef, _ := step["state_ref"].(string)
	if stateRef == "" {
		t.Fatal("state_ref missing from step body")
	}
	csrfCookie := findCookie(stepResp.Cookies(), "__Host-oidc_csrf")
	if csrfCookie == nil {
		t.Fatal("csrf cookie missing")
	}

	// 3: POST /interaction/{uid} with the SubjectAuthenticator
	// submission shape (subject + state_ref).
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
	defer postResp.Body.Close()
	finalResp := completeConsentIfPrompted(t, client, tk.Server.URL+location.Path, tk.Issuer, csrfCookie.Value, postResp)
	defer finalResp.Body.Close()
	if finalResp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(finalResp.Body)
		t.Fatalf("POST status=%d body=%s", finalResp.StatusCode, string(dump))
	}
	rpRedirect, err := finalResp.Location()
	if err != nil {
		t.Fatalf("Location after POST: %v", err)
	}
	code := rpRedirect.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", rpRedirect.String())
	}
	if rpRedirect.Query().Get("state") != "state-abc" {
		t.Errorf("state=%q", rpRedirect.Query().Get("state"))
	}

	// 4: POST /token to exchange the code for tokens.
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {rp.RedirectURIs[0]},
		"code_verifier": {e2eVerifier},
	}
	tokenReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(tokenForm.Encode()))
	if err != nil {
		t.Fatalf("NewRequest token: %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth(rp.ID, secret)
	tokenResp, err := client.Do(tokenReq)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("token status=%d body=%s", tokenResp.StatusCode, string(dump))
	}
	tokenBody := decodeMap(t, tokenResp)
	if at, _ := tokenBody["access_token"].(string); at == "" {
		t.Errorf("access_token missing: %v", tokenBody)
	}
	if idt, _ := tokenBody["id_token"].(string); idt == "" {
		t.Errorf("id_token missing: %v", tokenBody)
	}
}

// e2eAuthorizeValues returns the canonical happy-path query parameters
// for the end-to-end flow.
func e2eAuthorizeValues(clientID, redirectURI string) url.Values {
	return url.Values{
		"client_id":             {clientID},
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile email"},
		"state":                 {"state-abc"},
		"nonce":                 {"n-0S6_WzA2Mj"},
		"code_challenge":        {e2eChallenge()},
		"code_challenge_method": {"S256"},
	}
}

// httpRequestBuilder bundles a request URL with helpers for issuing it.
// Tests use it so each hop reads as one short call.
type httpRequestBuilder struct {
	url string
}

func newGet(url string) *httpRequestBuilder { return &httpRequestBuilder{url: url} }

func (b *httpRequestBuilder) Do(client *http.Client) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, b.url, http.NoBody)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

// decodeMap reads resp.Body as a JSON object map, failing the test on error.
func decodeMap(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal %s: %v", string(raw), err)
	}
	return out
}

// findCookie returns the cookie matching name, or nil. Used by tests
// that thread CSRF tokens between the GET /interaction prompt and
// the matching POST submission.
func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// completeConsentIfPrompted submits the built-in consent screen with
// every requested scope approved when prior is a consent prompt. The
// helper closes prior on dispatch and returns the chain's next
// response (typically the 302 redirect back to the RP). When prior is
// already a redirect or non-consent response, prior is returned
// unchanged so callers can keep a uniform Body close pattern.
func completeConsentIfPrompted(t *testing.T, client *http.Client, interactionURL, origin, csrf string, prior *http.Response) *http.Response {
	t.Helper()
	consent, env, err := testkit.IsConsentPrompt(prior)
	if err != nil {
		t.Fatalf("inspect consent prompt: %v", err)
	}
	if !consent {
		return prior
	}
	stateRef, _ := env["state_ref"].(string)
	if stateRef == "" {
		t.Fatal("consent prompt missing state_ref")
	}
	approved := approvedScopesFromPrompt(env)
	return testkit.PostConsentApproval(t, client, interactionURL, origin, csrf, stateRef, approved)
}

// approvedScopesFromPrompt extracts the requested scope names from
// the consent prompt envelope and returns them as a space-delimited
// string. Tests approve every requested scope; specific test cases
// that exercise scope dropping build their own subset.
func approvedScopesFromPrompt(env map[string]any) string {
	data, _ := env["data"].(map[string]any)
	scopesAny, _ := data["Scopes"].([]any)
	out := make([]string, 0, len(scopesAny))
	for _, s := range scopesAny {
		entry, _ := s.(map[string]any)
		name, _ := entry["Name"].(string)
		if name != "" {
			out = append(out, name)
		}
	}
	return strings.Join(out, " ")
}
