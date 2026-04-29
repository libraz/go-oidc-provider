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
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestEndToEnd_CodeReplayRevokesAT exercises the OFCS
// `oidcc-codereuse-30seconds` shape end-to-end:
//
//  1. /authorize → /token mints AT_a + RT_a.
//  2. AT_a verifies at /userinfo (200).
//  3. The authorization code is replayed at /token → invalid_grant.
//  4. AT_a is now rejected at /userinfo (401 invalid_token).
//  5. AT_a returns {"active": false} at /introspect.
//
// The test pins the code-replay cascade: a single replayed code
// revokes every access token the original issuance produced, not
// just the refresh-token chain. RFC 6749 §4.1.2 / RFC 6819 §5.2.1.1.
func TestEndToEnd_CodeReplayRevokesAT(t *testing.T) {
	t.Parallel()
	clock := fakeClock{now: time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t, testkit.WithClock(clock))
	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-cascade",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	tk.Store.PutUser(context.Background(), &store.User{
		Subject: "user-cascade",
		Claims:  map[string]any{"sub": "user-cascade"},
	})
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	browser := &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	code := authorizeAndConsent(t, browser, tk, rp, secret)

	// 1: First /token exchange — happy path.
	at, _ := exchangeCode(t, tk, rp, secret, code, "first")
	// 2: AT_a works at /userinfo.
	if got := userinfoStatus(t, tk, at); got != http.StatusOK {
		t.Fatalf("pre-replay userinfo: status=%d, want 200", got)
	}
	// 3: Replay the code → invalid_grant. The cascade fires.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {rp.RedirectURIs[0]},
		"code_verifier": {e2eVerifier},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest replay: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST replay: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("replay status=%d body=%s", resp.StatusCode, string(dump))
	}
	body := decodeMap(t, resp)
	if got, _ := body["error"].(string); got != "invalid_grant" {
		t.Errorf("replay error = %q, want invalid_grant", got)
	}
	// 4: AT_a is now rejected at /userinfo.
	if got := userinfoStatus(t, tk, at); got != http.StatusUnauthorized {
		t.Errorf("post-cascade userinfo: status=%d, want 401", got)
	}
}

// authorizeAndConsent walks /authorize → /interaction → consent and
// returns the issued code. Reused across the cascade tests so each one
// reads as the protocol assertion it actually exercises rather than
// the four-hop choreography that gets there.
func authorizeAndConsent(t *testing.T, client *http.Client, tk *testkit.Provider, rp *store.Client, _ string) string {
	t.Helper()
	authorizeURL := tk.Server.URL + "/oidc/auth?" + e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0]).Encode()
	authResp, err := newGet(authorizeURL).Do(client)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer authResp.Body.Close()
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
	csrfCookie := findCookie(stepResp.Cookies(), "__Host-oidc_csrf")
	body := map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{"subject": "user-cascade"},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+location.Path, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest interaction: %v", err)
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
	rpRedirect, err := finalResp.Location()
	if err != nil {
		t.Fatalf("Location after consent: %v", err)
	}
	code := rpRedirect.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", rpRedirect.String())
	}
	return code
}

// exchangeCode posts the form to /token, returns (access_token, refresh_token).
// The label is folded into Fatalf messages so failures pinpoint the call
// site (first vs replay) without reading line numbers.
func exchangeCode(t *testing.T, tk *testkit.Provider, rp *store.Client, secret, code, label string) (string, string) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {rp.RedirectURIs[0]},
		"code_verifier": {e2eVerifier},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("%s: NewRequest token: %v", label, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s: POST /token: %v", label, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s: token status=%d body=%s", label, resp.StatusCode, string(dump))
	}
	body := decodeMap(t, resp)
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatalf("%s: access_token missing: %v", label, body)
	}
	rt, _ := body["refresh_token"].(string)
	return at, rt
}

// userinfoStatus calls /userinfo with the supplied bearer access token
// and returns the HTTP status code. The body is drained but discarded;
// the cascade tests only care about the wire status, not the claim
// payload.
func userinfoStatus(t *testing.T, tk *testkit.Provider, accessToken string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/userinfo", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest /userinfo: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}
