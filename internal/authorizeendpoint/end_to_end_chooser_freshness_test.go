package authorizeendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
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
	mgr      *sessions.Manager
	entry    sessions.Outcome
	sibling  sessions.Outcome
}

func newChooserFreshnessFixture(t *testing.T, siblingLogin sessions.Login, opts ...op.Option) *chooserFreshnessFixture {
	t.Helper()
	clock := fakeClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	cookieKey := []byte(chooserCookieKey)
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(append([]op.Option{op.WithCookieKeys(cookieKey)}, opts...)...),
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
	entry := establishFresh(t, mgr, sessions.Login{
		Subject:  "user-entry",
		AuthTime: clock.now,
		ACR:      chooserStrongACR,
		AMR:      []string{"pwd"},
	}, clock.now)
	sibling := establishAddAccount(t, mgr, entry.Cookie, siblingLogin, clock.now)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &chooserFreshnessFixture{
		tk:       tk,
		clientID: rp.ID,
		redirect: rp.RedirectURIs[0],
		cl:       tk.HTTPClient(jar),
		mgr:      mgr,
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

// requireCredentialPrompt asserts the chooser submission continued into
// the credential factor rather than ending the request, and returns the
// prompt's state_ref.
func requireCredentialPrompt(t *testing.T, resp *http.Response) string {
	t.Helper()
	if resp.StatusCode == http.StatusFound {
		loc, _ := resp.Location()
		t.Fatalf("the request ended straight after the chooser (%v); the picked session must be re-authenticated", loc)
	}
	env := decodeMap(t, resp)
	if got, _ := env["type"].(string); got != testkit.SubjectPromptType {
		t.Fatalf("after the chooser the next prompt was %q; want the credential prompt %q", got, testkit.SubjectPromptType)
	}
	stateRef, _ := env["state_ref"].(string)
	return stateRef
}

// TestEndToEnd_ChooserPickStaleSession_MaxAgeNotBypassed asserts that
// picking an account whose authentication predates max_age re-runs the
// credential factor for that account instead of minting a code against
// the stale session. The entry session satisfies max_age, so nothing at
// the door catches this.
func TestEndToEnd_ChooserPickStaleSession_MaxAgeNotBypassed(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	f := newChooserFreshnessFixture(t, sessions.Login{
		Subject:  "user-stale",
		AuthTime: start.Add(-72 * time.Hour),
		ACR:      chooserStrongACR,
		AMR:      []string{"pwd"},
	})
	resp, interactionURL, _, interactionCookie := f.pickSibling(t, url.Values{
		"prompt":  {"select_account"},
		"max_age": {"60"},
	})
	defer resp.Body.Close()
	stateRef := requireCredentialPrompt(t, resp)

	// Re-authenticating the picked account completes the request.
	csrfCookie := findCookie(resp.Cookies(), cookie.CSRFProfile.Name)
	if csrfCookie == nil {
		t.Fatal("csrf cookie missing on the credential prompt")
	}
	raw, err := json.Marshal(map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{testkit.SubjectFieldName: "user-stale"},
	})
	if err != nil {
		t.Fatalf("marshal credential: %v", err)
	}
	ctx := context.Background()
	credReq, err := http.NewRequestWithContext(ctx, http.MethodPost, interactionURL, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest credential POST: %v", err)
	}
	credReq.Header.Set("Content-Type", "application/json")
	credReq.Header.Set("Origin", f.tk.Issuer)
	credReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	credReq.AddCookie(csrfCookie)
	credReq.AddCookie(interactionCookie)
	credReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: f.entry.Cookie})
	credResp, err := f.cl.Do(credReq)
	if err != nil {
		t.Fatalf("POST credential: %v", err)
	}
	defer credResp.Body.Close()
	final := postConsentWithSessionCookie(t, f.cl, ctx, interactionURL, f.tk.Issuer,
		csrfCookie, interactionCookie, f.entry.Cookie, credResp)
	defer final.Body.Close()
	if final.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(final.Body)
		t.Fatalf("after re-authentication: status=%d body=%s", final.StatusCode, dump)
	}
	loc, err := final.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if loc.Query().Get("code") == "" {
		t.Fatalf("re-authenticated pick did not mint a code: %s", loc)
	}

	// The browser is left on a record of the re-authentication, so the
	// same max_age is met silently on the next request.
	sessCookie := findCookie(final.Cookies(), cookie.SessionProfile.Name)
	if sessCookie == nil {
		t.Fatal("the re-authenticated pick set no session cookie")
	}
	active, err := f.mgr.Resolve(ctx, sessCookie.Value)
	if err != nil {
		t.Fatalf("Resolve the session cookie: %v", err)
	}
	if active.Session.Subject != "user-stale" || active.Session.ID == f.sibling.SessionID || !active.Session.AuthTime.Equal(start) {
		t.Fatalf("session after re-authentication: id=%q subject=%q auth_time=%v; want a new user-stale record at %v",
			active.Session.ID, active.Session.Subject, active.Session.AuthTime, start)
	}
	silent := f.authorizeWithSession(t, sessCookie.Value, url.Values{"prompt": {"none"}, "max_age": {"60"}})
	if silent.Query().Get("code") == "" {
		t.Fatalf("prompt=none with the same max_age after re-authentication: %s, want a code", silent)
	}
}

// TestEndToEnd_ChooserPickWeakSession_ACRNotBypassed is the RFC 9470
// counterpart: the picked session's recorded acr is outside the
// requested set, so the account is re-authenticated rather than served
// even though the entry session's acr satisfied the request.
func TestEndToEnd_ChooserPickWeakSession_ACRNotBypassed(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	f := newChooserFreshnessFixture(t, sessions.Login{
		Subject:  "user-weak",
		AuthTime: start,
		ACR:      chooserWeakACR,
		AMR:      []string{"pwd"},
	})
	resp, _, _, _ := f.pickSibling(t, url.Values{
		"prompt":     {"select_account"},
		"acr_values": {chooserStrongACR},
	})
	defer resp.Body.Close()
	requireCredentialPrompt(t, resp)
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

// TestEndToEnd_ChooserPickSignedOutBeforeCompletion pins that a picked
// session which is gone by the time the ceremony completes is answered
// the way the entry-session route answers it: a permanent
// login_required that retires the interaction record, not a retryable
// server_error.
func TestEndToEnd_ChooserPickSignedOutBeforeCompletion(t *testing.T) {
	t.Parallel()
	start := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)
	f := newChooserFreshnessFixture(t, sessions.Login{
		Subject:  "user-gone",
		AuthTime: start,
		ACR:      chooserStrongACR,
		AMR:      []string{"pwd"},
	})
	ctx := context.Background()
	postResp, interactionURL, csrfCookie, interactionCookie := f.pickSibling(t, url.Values{"prompt": {"select_account"}})
	defer postResp.Body.Close()
	if err := f.tk.Store.Sessions().Delete(ctx, f.sibling.SessionID); err != nil {
		t.Fatalf("Delete sibling session: %v", err)
	}
	resp := postConsentWithSessionCookie(t, f.cl, ctx, interactionURL, f.tk.Issuer,
		csrfCookie, interactionCookie, f.entry.Cookie, postResp)
	defer resp.Body.Close()
	requireRedirectError(t, resp, "login_required")

	uid := interactionURL[strings.LastIndex(interactionURL, "/")+1:]
	if _, err := f.tk.Store.Interactions().Find(ctx, uid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("interaction record after the refusal: err=%v, want it retired", err)
	}
}
