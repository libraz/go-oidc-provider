package authorizeendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestEndToEnd_OpenIDScopeOptional_PlainOAuth drives the full
// /authorize -> /interaction -> /token flow against an OP that has
// [op.WithOpenIDScopeOptional] active. The request omits the "openid"
// scope, so the OP must serve the request as plain RFC 6749 §4.1
// authorization_code: the token response carries an access_token but
// MUST NOT carry an id_token. The id_token issuance is scope-driven
// (see internal/tokenendpoint/authcode.go issueAuthCodeResponse), so
// the option's relaxation of the /authorize gate must compose with
// that gate without producing a stray id_token.
func TestEndToEnd_OpenIDScopeOptional_PlainOAuth(t *testing.T) {
	t.Parallel()

	clock := fakeClock{now: time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithOpenIDScopeOptional()),
	)
	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-oauth-only",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	values := e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0])
	values.Set("scope", "profile")
	// nonce is omitted because plain OAuth 2.0 has no id_token to
	// bind it to; the default policy treats nonce as optional, so
	// the request stays accepted without it.
	values.Del("nonce")

	tokenBody := runOpenIDOptionalAuthCodeFlow(t, tk, rp.ID, secret, rp.RedirectURIs[0], values)
	if at, _ := tokenBody["access_token"].(string); at == "" {
		t.Errorf("access_token missing: %v", tokenBody)
	}
	if idt, _ := tokenBody["id_token"].(string); idt != "" {
		// The spec contract is "no id_token without openid". Asserting
		// the field is absent (or empty when present as JSON null /
		// empty string) is the load-bearing claim; the rest of the
		// wire shape is intentionally not pinned here so future v1.0
		// adjustments to the JSON envelope stay free.
		t.Errorf("id_token MUST be absent for non-openid scope; got %q", idt)
	}
}

// TestEndToEnd_OpenIDScopeOptional_OIDCStillWorks confirms the
// option is opt-in PER REQUEST, not a global "no id_token" switch:
// the same OP that just served plain OAuth above MUST also serve a
// classic OIDC authorization_code request when "openid" is in scope.
// This pins that [op.WithOpenIDScopeOptional] only relaxes the
// /authorize gate and never suppresses id_token issuance.
func TestEndToEnd_OpenIDScopeOptional_OIDCStillWorks(t *testing.T) {
	t.Parallel()

	clock := fakeClock{now: time.Date(2026, 4, 30, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithOpenIDScopeOptional()),
	)
	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-mixed",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	// Standard OIDC request — scope keeps "openid", nonce present.
	values := e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0])
	tokenBody := runOpenIDOptionalAuthCodeFlow(t, tk, rp.ID, secret, rp.RedirectURIs[0], values)
	if at, _ := tokenBody["access_token"].(string); at == "" {
		t.Errorf("access_token missing: %v", tokenBody)
	}
	if idt, _ := tokenBody["id_token"].(string); idt == "" {
		t.Errorf("id_token MUST be present when openid is requested under WithOpenIDScopeOptional, got %v", tokenBody)
	}
}

// runOpenIDOptionalAuthCodeFlow drives the /authorize -> /interaction
// -> /token chain against tk and returns the decoded token-endpoint
// body. The helper exists so the two sibling tests
// ([TestEndToEnd_OpenIDScopeOptional_PlainOAuth] and
// [TestEndToEnd_OpenIDScopeOptional_OIDCStillWorks]) can vary only
// the input values without duplicating the cookie / CSRF / consent
// scaffolding. Behavioural assertions stay in each caller; the
// helper only fails when the chain itself is malformed (status mis-
// match, missing CSRF cookie, etc.).
func runOpenIDOptionalAuthCodeFlow(
	t *testing.T,
	tk *testkit.Provider,
	clientID, secret, redirectURI string,
	values url.Values,
) map[string]any {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

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
	if !strings.HasPrefix(location.Path, "/oidc/interaction/") {
		t.Fatalf("Location=%s", location.String())
	}

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

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {e2eVerifier},
	}
	tokenReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(tokenForm.Encode()))
	if err != nil {
		t.Fatalf("NewRequest token: %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth(clientID, secret)
	tokenResp, err := http.DefaultClient.Do(tokenReq)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("token status=%d body=%s", tokenResp.StatusCode, string(dump))
	}
	return decodeMap(t, tokenResp)
}
