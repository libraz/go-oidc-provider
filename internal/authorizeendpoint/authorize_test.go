package authorizeendpoint_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/pkce"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// fakeClock returns a fixed wall-clock reading; injecting it makes timing
// assertions deterministic.
type fakeClock struct{ now time.Time }

func (f fakeClock) Now() time.Time { return f.now }

// fixedNow is the canonical test clock used across the table tests.
func fixedNow() time.Time {
	return time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
}

// canonicalChallenge returns the S256 challenge for a fixed verifier so
// every test that needs a "good" PKCE challenge gets the same one.
func canonicalChallenge() string {
	verifier := strings.Repeat("a", 64)
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// testHarness bundles the handler under test plus the supporting machinery
// each test row consumes.
type testHarness struct {
	handler        http.Handler
	store          *inmem.Store
	cookieCodec    *cookie.Codec
	sessionMgr     *sessions.Manager
	csrfSigner     *csrf.Signer
	driver         interaction.Driver
	clock          *fakeClock
	authorizePath  string
	interactionPth string
}

// newHarness builds a handler against fresh in-memory infrastructure.
func newHarness(t *testing.T) *testHarness {
	t.Helper()
	clock := &fakeClock{now: fixedNow()}
	store := inmem.New(inmem.WithClock(clock))
	registerTestClient(t, store)

	cookieKey := make([]byte, 32)
	for i := range cookieKey {
		cookieKey[i] = byte(i + 1)
	}
	cookieCodec, err := cookie.NewCodec(cookieKey)
	if err != nil {
		t.Fatalf("cookie.NewCodec: %v", err)
	}
	sessCodec, err := sessions.NewCodec(cookieCodec)
	if err != nil {
		t.Fatalf("sessions.NewCodec: %v", err)
	}
	mgr, err := sessions.NewManager(sessions.Config{
		Codec: sessCodec,
		Store: store.Sessions(),
		Clock: clock.Now,
	})
	if err != nil {
		t.Fatalf("sessions.NewManager: %v", err)
	}
	csrfKey := make([]byte, 32)
	for i := range csrfKey {
		csrfKey[i] = byte(i + 100)
	}
	signer, err := csrf.NewSigner(csrfKey)
	if err != nil {
		t.Fatalf("csrf.NewSigner: %v", err)
	}
	allow, err := csrf.NewAllowlist([]string{"https://op.example.com"})
	if err != nil {
		t.Fatalf("csrf.NewAllowlist: %v", err)
	}

	deps := authorizeendpoint.Deps{
		Clients:         store.Clients(),
		Codes:           store.AuthorizationCodes(),
		Grants:          store.Grants(),
		Interactions:    store.Interactions(),
		Sessions:        mgr,
		CookieCodec:     cookieCodec,
		CSRF:            signer,
		Origins:         allow,
		Driver:          interaction.NoopDriver{},
		AuthorizePath:   "/oidc/auth",
		InteractionPath: "/oidc/interaction",
		Clock:           clock,
	}

	return &testHarness{
		handler:        authorizeendpoint.Handler(deps),
		store:          store,
		cookieCodec:    cookieCodec,
		sessionMgr:     mgr,
		csrfSigner:     signer,
		driver:         interaction.NoopDriver{},
		clock:          clock,
		authorizePath:  deps.AuthorizePath,
		interactionPth: deps.InteractionPath,
	}
}

// registerTestClient seeds the store with the canonical RP fixture every
// test row uses.
func registerTestClient(t *testing.T, st *inmem.Store) {
	t.Helper()
	c := &store.Client{
		ID:                      "client-1",
		RedirectURIs:            []string{"https://rp.example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	if err := st.RegisterClient(context.Background(), c); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
}

// goodAuthorizeValues returns the canonical happy-path query parameters.
func goodAuthorizeValues() url.Values {
	return url.Values{
		"client_id":             {"client-1"},
		"response_type":         {"code"},
		"redirect_uri":          {"https://rp.example.com/cb"},
		"scope":                 {"openid profile"},
		"state":                 {"state-abc"},
		"nonce":                 {"n-0S6_WzA2Mj"},
		"code_challenge":        {canonicalChallenge()},
		"code_challenge_method": {pkce.Method},
	}
}

// doAuthorizeGET issues a GET /authorize with the supplied query values.
func doAuthorizeGET(t *testing.T, h *testHarness, values url.Values) *http.Response {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+values.Encode(), http.NoBody)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	return w.Result()
}

func TestAuthorize_NoSession_RedirectsToInteraction(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	resp := doAuthorizeGET(t, h, goodAuthorizeValues())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, h.interactionPth+"/") {
		t.Errorf("Location=%q want prefix %s/", loc, h.interactionPth)
	}
	// Interaction cookie must be set.
	if !hasCookie(resp, cookie.InteractionProfile.Name) {
		t.Errorf("interaction cookie missing: %v", resp.Cookies())
	}
}

func TestAuthorize_PromptNoneNoSession_RedirectsLoginRequired(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	v := goodAuthorizeValues()
	v.Set("prompt", "none")
	resp := doAuthorizeGET(t, h, v)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	loc := mustParseLocation(t, resp)
	if got := loc.Query().Get("error"); got != "login_required" {
		t.Errorf("error=%q want login_required", got)
	}
	if got := loc.Query().Get("state"); got != "state-abc" {
		t.Errorf("state=%q", got)
	}
}

func TestAuthorize_RejectsUnknownClient(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	v := goodAuthorizeValues()
	v.Set("client_id", "nonexistent")
	resp := doAuthorizeGET(t, h, v)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := readJSON(t, resp)
	if body["error"] != "invalid_request" {
		t.Errorf("error=%v", body["error"])
	}
}

func TestAuthorize_RejectsBadRedirectURIWithJSON(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	v := goodAuthorizeValues()
	v.Set("redirect_uri", "https://evil.example.com/cb")
	resp := doAuthorizeGET(t, h, v)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := readJSON(t, resp)
	if body["error"] != "invalid_request" {
		t.Errorf("error=%v want invalid_request", body["error"])
	}
}

func TestAuthorize_RejectsBadResponseTypeWithRedirect(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	v := goodAuthorizeValues()
	v.Set("response_type", "token")
	resp := doAuthorizeGET(t, h, v)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	loc := mustParseLocation(t, resp)
	if got := loc.Query().Get("error"); got != "unsupported_response_type" {
		t.Errorf("error=%q", got)
	}
}

func TestAuthorize_RejectsPostWithoutFormContent(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, h.authorizePath, strings.NewReader(""))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestAuthorize_RejectsBadMethod(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPut, h.authorizePath, http.NoBody)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); got == "" {
		t.Error("Allow header missing")
	}
}

func TestAuthorize_HappyPathWithExistingSessionAndGrant_MintsCode(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	// Seed an active session and a covering grant; the dispatcher should
	// then mint a code and redirect to the RP without an interaction.
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-1",
		AuthTime: h.clock.now.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := h.store.Grants().Save(context.Background(), &store.Grant{
		ID:        "grant-1",
		Subject:   "user-1",
		ClientID:  "client-1",
		Scope:     []string{"openid", "profile", "email"},
		CreatedAt: h.clock.now,
		UpdatedAt: h.clock.now,
	}); err != nil {
		t.Fatalf("Save grant: %v", err)
	}

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+goodAuthorizeValues().Encode(), http.NoBody)
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	loc := mustParseLocation(t, resp)
	if loc.Query().Get("code") == "" {
		t.Fatalf("code missing from %s", loc.String())
	}
	if loc.Query().Get("state") != "state-abc" {
		t.Errorf("state=%q", loc.Query().Get("state"))
	}
	// The persisted code must reference the grant and the request scope.
	codeID := loc.Query().Get("code")
	rec, err := h.store.AuthorizationCodes().Find(context.Background(), codeID)
	if err != nil {
		t.Fatalf("Find code: %v", err)
	}
	if rec.GrantID != "grant-1" || rec.Subject != "user-1" {
		t.Errorf("code=%+v", rec)
	}
}

func TestAuthorize_PromptLoginForcesInteraction_EvenWithSession(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-1",
		AuthTime: h.clock.now,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	v := goodAuthorizeValues()
	v.Set("prompt", "login")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+v.Encode(), http.NoBody)
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	loc := mustParseLocation(t, resp)
	if !strings.HasPrefix(loc.Path, h.interactionPth+"/") {
		t.Errorf("Location=%s want interaction redirect", loc.String())
	}
}

func TestAuthorize_MaxAgeViolationForcesInteraction(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	// Issue a session whose AuthTime is well in the past.
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-1",
		AuthTime: h.clock.now.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := h.store.Grants().Save(context.Background(), &store.Grant{
		ID:        "grant-1",
		Subject:   "user-1",
		ClientID:  "client-1",
		Scope:     []string{"openid", "profile"},
		CreatedAt: h.clock.now,
		UpdatedAt: h.clock.now,
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	v := goodAuthorizeValues()
	v.Set("max_age", "60") // older than 1 hour by far
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+v.Encode(), http.NoBody)
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	loc := mustParseLocation(t, resp)
	if !strings.HasPrefix(loc.Path, h.interactionPth+"/") {
		t.Errorf("Location=%s want interaction redirect", loc.String())
	}
}

// newScopeHarness builds a handler whose Deps include a registry that
// locks billing:write to a single client. The fixture client (client-1)
// is granted billing:write in its registered Scopes so the
// AllowedClients allowlist is the only barrier left for the test rows
// to exercise.
func newScopeHarness(t *testing.T) *testHarness {
	t.Helper()
	clock := &fakeClock{now: fixedNow()}
	st := inmem.New(inmem.WithClock(clock))
	if err := st.RegisterClient(context.Background(), &store.Client{
		ID:                      "client-1",
		RedirectURIs:            []string{"https://rp.example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email", "billing:write"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	cookieKey := make([]byte, 32)
	for i := range cookieKey {
		cookieKey[i] = byte(i + 1)
	}
	cookieCodec, err := cookie.NewCodec(cookieKey)
	if err != nil {
		t.Fatalf("cookie.NewCodec: %v", err)
	}
	sessCodec, err := sessions.NewCodec(cookieCodec)
	if err != nil {
		t.Fatalf("sessions.NewCodec: %v", err)
	}
	mgr, err := sessions.NewManager(sessions.Config{
		Codec: sessCodec,
		Store: st.Sessions(),
		Clock: clock.Now,
	})
	if err != nil {
		t.Fatalf("sessions.NewManager: %v", err)
	}
	csrfKey := make([]byte, 32)
	for i := range csrfKey {
		csrfKey[i] = byte(i + 100)
	}
	signer, err := csrf.NewSigner(csrfKey)
	if err != nil {
		t.Fatalf("csrf.NewSigner: %v", err)
	}
	allow, err := csrf.NewAllowlist([]string{"https://op.example.com"})
	if err != nil {
		t.Fatalf("csrf.NewAllowlist: %v", err)
	}

	scopes := scoperegistry.New([]scoperegistry.Entry{
		{Name: "billing:write", Public: true, AllowedClients: []string{"svc-billing"}},
	})

	deps := authorizeendpoint.Deps{
		Clients:         st.Clients(),
		Codes:           st.AuthorizationCodes(),
		Grants:          st.Grants(),
		Interactions:    st.Interactions(),
		Sessions:        mgr,
		CookieCodec:     cookieCodec,
		CSRF:            signer,
		Origins:         allow,
		Driver:          interaction.NoopDriver{},
		Scopes:          scopes,
		AuthorizePath:   "/oidc/auth",
		InteractionPath: "/oidc/interaction",
		Clock:           clock,
	}

	return &testHarness{
		handler:        authorizeendpoint.Handler(deps),
		store:          st,
		cookieCodec:    cookieCodec,
		sessionMgr:     mgr,
		csrfSigner:     signer,
		driver:         interaction.NoopDriver{},
		clock:          clock,
		authorizePath:  deps.AuthorizePath,
		interactionPth: deps.InteractionPath,
	}
}

// TestAuthorize_ScopeAllowedClients_RedirectsInvalidScope is the HTTP
// surface counterpart of the validator-level test in
// internal/authorize. The /authorize endpoint MUST surface the
// AllowedClients violation as a redirect with error=invalid_scope
// because redirect_uri has already been verified by the time the scope
// check runs (ErrScopeClientNotAllowed is redirect-safe).
func TestAuthorize_ScopeAllowedClients_RedirectsInvalidScope(t *testing.T) {
	t.Parallel()

	h := newScopeHarness(t)
	v := goodAuthorizeValues()
	v.Set("scope", "openid billing:write")

	resp := doAuthorizeGET(t, h, v)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	loc := mustParseLocation(t, resp)
	if got := loc.Query().Get("error"); got != "invalid_scope" {
		t.Errorf("error=%q want invalid_scope", got)
	}
	if got := loc.Query().Get("state"); got != "state-abc" {
		t.Errorf("state=%q want state-abc", got)
	}
	// The Location host must be the registered redirect_uri host;
	// otherwise the OP misclassified the error as pre-redirect-URI.
	if loc.Host != "rp.example.com" {
		t.Errorf("redirect host=%q want rp.example.com", loc.Host)
	}
}

// hasCookie reports whether resp set a cookie with the given name.
func hasCookie(resp *http.Response, name string) bool {
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return true
		}
	}
	return false
}

// mustParseLocation parses the Location header, failing the test on error.
func mustParseLocation(t *testing.T, resp *http.Response) *url.URL {
	t.Helper()
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	return loc
}

// readJSON decodes the response body into a map.
func readJSON(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("unmarshal %q: %v", string(body), err)
	}
	return out
}
