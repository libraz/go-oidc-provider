package authorizeendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// The account chooser can bind a session other than the one the request
// arrived with, so the freshness and authentication-context constraints
// the dispatcher evaluated at the door do not automatically hold for the
// session that ends up backing the response. These tests pin that they
// are re-applied to the picked session on every exit path that would
// otherwise emit a code.

const (
	chooserStrongACR = "urn:example:strong"
	chooserWeakACR   = "urn:example:weak"
)

// chooserFreshnessFixture is a provider with two accounts in one chooser
// group: the cookie-resolved account (fresh, strong acr) and a sibling
// whose assurance the test varies.
type chooserFreshnessFixture struct {
	tk       *testkit.Provider
	clientID string
	redirect string
	cl       *http.Client
	entry    sessions.Outcome
	sibling  sessions.Outcome
}

func newChooserFreshnessFixture(t *testing.T, siblingLogin sessions.Login) *chooserFreshnessFixture {
	t.Helper()
	clock := fakeClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	cookieKey := []byte(chooserCookieKey)
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithCookieKeys(cookieKey)),
	)
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash("rp-secret")
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-chooser-freshness",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	mgr, _ := newChooserSessionsManager(t, tk.Store.Sessions(), cookieKey, clock)
	ctx := context.Background()
	entry, err := mgr.Issue(ctx, sessions.Login{
		Subject:  "user-entry",
		AuthTime: clock.now,
		ACR:      chooserStrongACR,
		AMR:      []string{"pwd"},
	})
	if err != nil {
		t.Fatalf("Issue entry session: %v", err)
	}
	sibling, err := mgr.AddAccount(ctx, entry.ChooserGroupID, siblingLogin)
	if err != nil {
		t.Fatalf("AddAccount sibling: %v", err)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &chooserFreshnessFixture{
		tk:       tk,
		clientID: rp.ID,
		redirect: rp.RedirectURIs[0],
		cl:       tk.HTTPClient(jar),
		entry:    entry,
		sibling:  sibling,
	}
}

// pickSibling drives /authorize with the supplied extra parameters,
// walks to the chooser prompt, and submits the sibling session. It
// returns the response the chooser submission produced plus the handles
// needed to keep walking the ceremony.
func (f *chooserFreshnessFixture) pickSibling(t *testing.T, extra url.Values) (*http.Response, string, *http.Cookie, *http.Cookie) {
	t.Helper()
	ctx := context.Background()
	values := e2eAuthorizeValues(f.clientID, f.redirect)
	for k, v := range extra {
		values[k] = v
	}
	authReq, err := http.NewRequestWithContext(ctx, http.MethodGet,
		f.tk.Server.URL+"/oidc/auth?"+values.Encode(), http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest /authorize: %v", err)
	}
	authReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: f.entry.Cookie})
	authResp, err := f.cl.Do(authReq)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(authResp.Body)
		t.Fatalf("authorize status=%d body=%s", authResp.StatusCode, string(dump))
	}
	loc, err := authResp.Location()
	if err != nil {
		t.Fatalf("authorize Location: %v", err)
	}
	if code := loc.Query().Get("code"); code != "" {
		t.Fatalf("authorize minted a code without running the chooser: %s", loc)
	}
	interactionURL := f.tk.Server.URL + loc.Path
	interactionCookie := findCookie(authResp.Cookies(), cookie.InteractionProfile.Name)
	if interactionCookie == nil {
		t.Fatal("__Host-oidc_interaction cookie missing")
	}

	stepReq, err := http.NewRequestWithContext(ctx, http.MethodGet, interactionURL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest interaction: %v", err)
	}
	stepReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: f.entry.Cookie})
	stepReq.AddCookie(interactionCookie)
	stepResp, err := f.cl.Do(stepReq)
	if err != nil {
		t.Fatalf("GET interaction: %v", err)
	}
	defer stepResp.Body.Close()
	step := decodeMap(t, stepResp)
	if got, _ := step["type"].(string); got != "interaction.chooser" {
		t.Fatalf("prompt type=%q want interaction.chooser", got)
	}
	stateRef, _ := step["state_ref"].(string)
	csrfCookie := findCookie(stepResp.Cookies(), cookie.CSRFProfile.Name)
	if csrfCookie == nil {
		t.Fatal("csrf cookie missing on chooser prompt")
	}

	raw, err := json.Marshal(map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{"session_id": f.sibling.SessionID},
	})
	if err != nil {
		t.Fatalf("marshal chooser submission: %v", err)
	}
	postReq, err := http.NewRequestWithContext(ctx, http.MethodPost, interactionURL, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest chooser POST: %v", err)
	}
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Origin", f.tk.Issuer)
	postReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	postReq.AddCookie(csrfCookie)
	postReq.AddCookie(interactionCookie)
	postReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: f.entry.Cookie})
	postResp, err := f.cl.Do(postReq)
	if err != nil {
		t.Fatalf("POST chooser: %v", err)
	}
	return postResp, interactionURL, csrfCookie, interactionCookie
}

// pickSiblingAndFinish runs pickSibling and then walks the consent
// ceremony the picked (grant-less) subject triggers, so the assertion
// lands on the request's terminal outcome.
func (f *chooserFreshnessFixture) pickSiblingAndFinish(t *testing.T, extra url.Values) *http.Response {
	t.Helper()
	postResp, interactionURL, csrfCookie, interactionCookie := f.pickSibling(t, extra)
	defer postResp.Body.Close()
	return postConsentWithSessionCookie(t, f.cl, context.Background(), interactionURL, f.tk.Issuer,
		csrfCookie, interactionCookie, f.entry.Cookie, postResp)
}

// requireRedirectError asserts the response is a redirect back to the RP
// carrying the expected OAuth error and no authorization code.
func requireRedirectError(t *testing.T, resp *http.Response, wantError string) {
	t.Helper()
	if resp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 302 redirect carrying %s; body=%s", resp.StatusCode, wantError, string(dump))
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if code := loc.Query().Get("code"); code != "" {
		t.Fatalf("an authorization code was issued for a session that fails the request's constraints: %s", loc)
	}
	if got := loc.Query().Get("error"); got != wantError {
		t.Fatalf("error=%q want %q (redirect %s)", got, wantError, loc)
	}
}

// TestEndToEnd_ChooserPickStaleSession_MaxAgeNotBypassed asserts that
// picking an account whose authentication predates max_age terminates
// the request instead of minting a code against the stale session. The
// entry session satisfies max_age, so nothing at the door catches this.
func TestEndToEnd_ChooserPickStaleSession_MaxAgeNotBypassed(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	f := newChooserFreshnessFixture(t, sessions.Login{
		Subject:  "user-stale",
		AuthTime: start.Add(-72 * time.Hour),
		ACR:      chooserStrongACR,
		AMR:      []string{"pwd"},
	})
	resp := f.pickSiblingAndFinish(t, url.Values{
		"prompt":  {"select_account"},
		"max_age": {"60"},
	})
	defer resp.Body.Close()
	requireRedirectError(t, resp, "login_required")
}

// TestEndToEnd_ChooserPickWeakSession_ACRNotBypassed is the RFC 9470
// counterpart: the picked session's recorded acr is outside the
// requested set, so no code may be issued for it even though the entry
// session's acr satisfied the request.
func TestEndToEnd_ChooserPickWeakSession_ACRNotBypassed(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	f := newChooserFreshnessFixture(t, sessions.Login{
		Subject:  "user-weak",
		AuthTime: start,
		ACR:      chooserWeakACR,
		AMR:      []string{"pwd"},
	})
	resp := f.pickSiblingAndFinish(t, url.Values{
		"prompt":     {"select_account"},
		"acr_values": {chooserStrongACR},
	})
	defer resp.Body.Close()
	requireRedirectError(t, resp, "unmet_authentication_requirements")
}

// TestEndToEnd_ChooserWithPromptLogin_RunsFactorChain asserts that
// combining prompt=login with select_account does not let the chooser
// stand in for the credential: after the account is picked, the factor
// chain still runs. Terminating right after the chooser would hand the
// RP a code for an authentication that happened days ago while it
// explicitly asked for a fresh one.
func TestEndToEnd_ChooserWithPromptLogin_RunsFactorChain(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	f := newChooserFreshnessFixture(t, sessions.Login{
		Subject:  "user-stale",
		AuthTime: start.Add(-72 * time.Hour),
		ACR:      chooserStrongACR,
		AMR:      []string{"pwd"},
	})
	resp, _, _, _ := f.pickSibling(t, url.Values{"prompt": {"login select_account"}})
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusFound {
		loc, _ := resp.Location()
		t.Fatalf("the chain terminated straight after the chooser (%v); prompt=login demands a credential", loc)
	}
	env := decodeMap(t, resp)
	promptType, _ := env["type"].(string)
	if promptType != testkit.SubjectPromptType {
		t.Fatalf("after the chooser the next prompt was %q; want the credential prompt %q",
			promptType, testkit.SubjectPromptType)
	}
}
