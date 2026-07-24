package authorizeendpoint_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/pkce"
	"github.com/libraz/go-oidc-provider/internal/proxy"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
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
	deps           authorizeendpoint.Deps
	store          *inmem.Store
	cookieCodec    *cookie.Codec
	sessionMgr     *sessions.Manager
	csrfSigner     *csrf.Signer
	driver         interaction.Driver
	orchestrator   *authn.Orchestrator
	clock          *fakeClock
	authorizePath  string
	interactionPth string
}

// buildTestOrchestrator constructs the chain runner the harness
// installs in [authorizeendpoint.Deps]. The orchestrator is wired
// with a single [testkit.SubjectAuthenticator] so /interaction is
// driven by a deterministic factor that binds whatever subject the
// test echoes through the form.
func buildTestOrchestrator(t *testing.T) *authn.Orchestrator {
	t.Helper()
	signer, err := authn.NewStateRefSigner(bytes.Repeat([]byte{0xCD}, 32))
	if err != nil {
		t.Fatalf("authn.NewStateRefSigner: %v", err)
	}
	orch, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{testkit.SubjectAuthenticator{}},
		StateRefSigner: signer,
	})
	if err != nil {
		t.Fatalf("authn.New: %v", err)
	}
	return orch
}

// newHarness builds a handler against fresh in-memory infrastructure.
// Optional customise hooks mutate the [authorizeendpoint.Deps] before the
// handler is built so individual tests can enable opt-in surfaces (e.g. the
// RFC 9396 authorization_details registry) without forking the harness.
func newHarness(t *testing.T, customise ...func(*authorizeendpoint.Deps)) *testHarness {
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
		Clock: func() time.Time { return clock.now },
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

	orch := buildTestOrchestrator(t)
	deps := authorizeendpoint.Deps{
		Clients:         store.Clients(),
		Codes:           store.AuthorizationCodes(),
		Grants:          store.Grants(),
		Transactions:    store,
		Interactions:    store.Interactions(),
		Sessions:        mgr,
		CookieCodec:     cookieCodec,
		CSRF:            signer,
		Origins:         allow,
		Driver:          interaction.JSONDriver{},
		Authn:           orch,
		AuthorizePath:   "/oidc/auth",
		InteractionPath: "/oidc/interaction",
		Clock:           clock,
		CompletionKey:   bytes.Repeat([]byte{0xE1}, 32),
	}
	for _, c := range customise {
		if c != nil {
			c(&deps)
		}
	}

	return &testHarness{
		handler:        authorizeendpoint.Handler(deps),
		deps:           deps,
		store:          store,
		cookieCodec:    cookieCodec,
		sessionMgr:     mgr,
		csrfSigner:     signer,
		driver:         interaction.JSONDriver{},
		orchestrator:   orch,
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

// TestAuthorize_RejectsBadRedirectURIWithJSON pins the open-redirect-on-
// error gate: when the redirect_uri does not resolve to a registered
// value it is never used as a redirect target. The OP renders a
// first-party 400 JSON error instead of bouncing the user agent to the
// unvalidated URL. Paired with TestAuthorize_RejectsBadResponseTypeWith-
// Redirect (a *validated* redirect_uri does carry the error back), the
// two pin the invariant: an error is only redirected once the redirect
// target has passed registration validation.
//
// Tracks: CVE-2026-44681 (Authlib) — a malformed authorization request
// (implicit/hybrid grant with the openid scope omitted) was redirected
// to a fully attacker-chosen URL. The structural property is that an
// unvalidated redirect target must produce a first-party error page,
// never a redirect.
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

func TestAuthorize_HappyPathWithExistingSessionAndGrant_EmitsCodeIssued(t *testing.T) {
	t.Parallel()

	emitter := &recordingEmitter{}
	h := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.Audit = emitter
	})
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

	ev := findRecordedAuditEvent(emitter.snapshot(), "code.issued")
	if ev == nil {
		t.Fatalf("code.issued not emitted; got=%v", emitter.snapshot())
	}
	if ev.ActorID != "user-1" {
		t.Errorf("ActorID=%q want user-1", ev.ActorID)
	}
	if ev.ClientID != "client-1" {
		t.Errorf("ClientID=%q want client-1", ev.ClientID)
	}
	if ev.SessionID != out.SessionID {
		t.Errorf("SessionID=%q want %q", ev.SessionID, out.SessionID)
	}
	if got := ev.Extras["grant_id"]; got != "grant-1" {
		t.Errorf("extras.grant_id=%v want grant-1", got)
	}
}

func TestAuthorize_ExistingSessionTouchesIdleExpiry(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
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
	h.clock.now = h.clock.now.Add(time.Hour)

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
	got, err := h.store.Sessions().Find(context.Background(), out.SessionID)
	if err != nil {
		t.Fatalf("Find session: %v", err)
	}
	want := h.clock.now.Add(sessions.IdleTTLDefault)
	if !got.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt=%v want %v", got.ExpiresAt, want)
	}
}

func findRecordedAuditEvent(events []audit.Event, name string) *audit.Event {
	for i := range events {
		if events[i].Name == name {
			return &events[i]
		}
	}
	return nil
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

func TestAuthorize_MaxAgeZeroForcesInteraction(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-1",
		AuthTime: h.clock.now,
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
	v.Set("max_age", "0")
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

func TestAuthorize_ACRUnsatisfiedForcesInteraction(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	// Session was authenticated at a weaker context than the RP now
	// requests; RFC 9470 step-up must re-run the authn chain rather than
	// silently mint against the weaker session.
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-1",
		AuthTime: h.clock.now,
		ACR:      "urn:acr:low",
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
	v.Set("acr_values", "urn:acr:high")
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

func TestAuthorize_ClaimsEssentialACRUnsatisfiedForcesInteraction(t *testing.T) {
	t.Parallel()

	h := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.ClaimsParameterEnabled = true
	})
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-1",
		AuthTime: h.clock.now,
		ACR:      "urn:acr:low",
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
	v.Set("claims", `{"id_token":{"acr":{"essential":true,"values":["urn:acr:high"]}}}`)
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

func TestAuthorize_ACRSatisfiedSession_MintsCode(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	// The session's recorded ACR is already one of the requested
	// acr_values, so the dispatcher mints silently without a step-up.
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-1",
		AuthTime: h.clock.now,
		ACR:      "urn:acr:high",
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
	v.Set("acr_values", "urn:acr:mid urn:acr:high")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+v.Encode(), http.NoBody)
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	loc := mustParseLocation(t, resp)
	if loc.Query().Get("code") == "" {
		t.Fatalf("code missing from %s", loc.String())
	}
}

func TestAuthorize_PromptNoneACRUnsatisfied_RedirectsInteractionRequired(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	// prompt=none forbids an interaction; a session too weak for the
	// requested acr_values resolves to interaction_required (§9①),
	// distinct from the login_required a max_age expiry would yield.
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-1",
		AuthTime: h.clock.now,
		ACR:      "urn:acr:low",
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
	v.Set("prompt", "none")
	v.Set("acr_values", "urn:acr:high")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+v.Encode(), http.NoBody)
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: out.Cookie})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	loc := mustParseLocation(t, resp)
	if got := loc.Query().Get("error"); got != "interaction_required" {
		t.Errorf("error=%q want interaction_required", got)
	}
}

func TestAuthorize_ClientDefaultsPopulateInteractionState(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	maxAge := int64(0)
	client, err := h.store.Clients().GetClient(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	client.DefaultMaxAge = &maxAge
	client.DefaultACRValues = []string{"urn:test:acr:loa2"}
	if err := h.store.UpdateClient(context.Background(), client); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}

	start := startInteractionFlow(t, h)
	rec, err := h.store.Interactions().Find(context.Background(), start.uid)
	if err != nil {
		t.Fatalf("Find interaction: %v", err)
	}
	state, err := authorize.UnmarshalState(rec.RawState)
	if err != nil {
		t.Fatalf("UnmarshalState: %v", err)
	}
	got := state.Library.ToRequest()
	if got.MaxAge == nil || *got.MaxAge != 0 {
		t.Fatalf("MaxAge=%v want pointer to 0", got.MaxAge)
	}
	if len(got.ACRValues) != 1 || got.ACRValues[0] != "urn:test:acr:loa2" {
		t.Fatalf("ACRValues=%v want [urn:test:acr:loa2]", got.ACRValues)
	}
}

type grantLookupFaultStore struct {
	store.GrantStore
	err error
}

type grantLookupCorruptStore struct {
	store.GrantStore
	result *store.Grant
}

func (s grantLookupCorruptStore) FindBySubjectClient(
	context.Context,
	string,
	string,
) (*store.Grant, error) {
	return s.result, nil
}

func (s grantLookupFaultStore) FindBySubjectClient(
	context.Context,
	string,
	string,
) (*store.Grant, error) {
	return nil, s.err
}

func TestAuthorize_GrantLookupFaultIsServerErrorNotMissingConsent(t *testing.T) {
	t.Parallel()

	injected := errors.New("injected grant lookup failure")
	h := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.Grants = grantLookupFaultStore{GrantStore: d.Grants, err: injected}
	})
	session, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-1",
		AuthTime: h.clock.now.Add(-time.Minute),
		AMR:      []string{"pwd"},
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	values := goodAuthorizeValues()
	values.Set("prompt", "none")
	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		h.authorizePath+"?"+values.Encode(),
		http.NoBody,
	)
	req.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: session.Cookie})
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := loc.Query().Get("error"); got != "server_error" {
		t.Errorf("error=%q want server_error; Location=%q", got, loc.String())
	}
	if strings.HasPrefix(loc.Path, h.interactionPth+"/") {
		t.Fatalf("grant backend failure started consent interaction: %s", loc.String())
	}
}

func TestAuthorize_CorruptGrantLookupIsServerErrorNotMissingConsent(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		result *store.Grant
	}{
		{name: "nil record"},
		{
			name: "mismatched record",
			result: &store.Grant{
				ID:       "grant-wrong-owner",
				Subject:  "other-user",
				ClientID: "client-1",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t, func(d *authorizeendpoint.Deps) {
				d.Grants = grantLookupCorruptStore{
					GrantStore: d.Grants,
					result:     tc.result,
				}
			})
			session, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
				Subject:  "user-1",
				AuthTime: h.clock.now.Add(-time.Minute),
			})
			if err != nil {
				t.Fatalf("Issue: %v", err)
			}
			values := goodAuthorizeValues()
			values.Set("prompt", "none")
			req := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodGet,
				h.authorizePath+"?"+values.Encode(),
				http.NoBody,
			)
			req.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: session.Cookie})
			rr := httptest.NewRecorder()
			h.handler.ServeHTTP(rr, req)
			if rr.Code != http.StatusFound {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			location, err := url.Parse(rr.Header().Get("Location"))
			if err != nil {
				t.Fatalf("parse Location: %v", err)
			}
			if got := location.Query().Get("error"); got != "server_error" {
				t.Fatalf("error=%q want server_error; Location=%q", got, location.String())
			}
		})
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
		Clock: func() time.Time { return clock.now },
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

	orch := buildTestOrchestrator(t)
	deps := authorizeendpoint.Deps{
		Clients:         st.Clients(),
		Codes:           st.AuthorizationCodes(),
		Grants:          st.Grants(),
		Interactions:    st.Interactions(),
		Sessions:        mgr,
		CookieCodec:     cookieCodec,
		CSRF:            signer,
		Origins:         allow,
		Driver:          interaction.JSONDriver{},
		Authn:           orch,
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
		driver:         interaction.JSONDriver{},
		orchestrator:   orch,
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

// TestAuthorize_TrustedProxy_HonoursXFFForRemoteIP pins the H-C5
// hardening: when [Deps.ProxyTrust] is configured and the request
// arrives from a CIDR inside the trust, the persisted authn state
// records the X-Forwarded-For client IP rather than the proxy IP.
// Without the trust the brute-force counter / audit log would
// attribute every authenticate request to the LB IP, hiding the real
// client.
func TestAuthorize_TrustedProxy_HonoursXFFForRemoteIP(t *testing.T) {
	t.Parallel()

	h := newHarnessWithProxyTrust(t)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+goodAuthorizeValues().Encode(), http.NoBody)
	r.RemoteAddr = "10.1.2.3:54321" // inside trusted CIDR
	r.Header.Set("X-Forwarded-For", "203.0.113.42")
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	uid := strings.TrimPrefix(loc.Path, h.interactionPth+"/")
	if uid == "" {
		t.Fatalf("could not extract uid from %s", loc.Path)
	}

	rec, err := h.store.Interactions().Find(context.Background(), uid)
	if err != nil {
		t.Fatalf("Find interaction: %v", err)
	}
	state, err := authorize.UnmarshalState(rec.RawState)
	if err != nil {
		t.Fatalf("UnmarshalState: %v", err)
	}
	var as authn.State
	if err := json.Unmarshal(state.Authn, &as); err != nil {
		t.Fatalf("decode authn state: %v", err)
	}
	if got := as.RemoteIP.String(); got != "203.0.113.42" {
		t.Errorf("RemoteIP=%q want 203.0.113.42 (XFF first non-trusted hop)", got)
	}
}

// TestAuthorize_TrustedProxy_IgnoresXFFFromUntrustedSource confirms
// the negative branch: a request whose RemoteAddr lies outside the
// trust cannot inject an XFF value. The persisted state must hold the
// RemoteAddr verbatim.
func TestAuthorize_TrustedProxy_IgnoresXFFFromUntrustedSource(t *testing.T) {
	t.Parallel()

	h := newHarnessWithProxyTrust(t)

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.authorizePath+"?"+goodAuthorizeValues().Encode(), http.NoBody)
	r.RemoteAddr = "203.0.113.5:54321" // OUTSIDE trusted CIDR
	r.Header.Set("X-Forwarded-For", "192.0.2.42")
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	uid := strings.TrimPrefix(loc.Path, h.interactionPth+"/")

	rec, err := h.store.Interactions().Find(context.Background(), uid)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	state, _ := authorize.UnmarshalState(rec.RawState)
	var as authn.State
	if err := json.Unmarshal(state.Authn, &as); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := as.RemoteIP.String(); got != "203.0.113.5" {
		t.Errorf("RemoteIP=%q want 203.0.113.5 (XFF spoof rejected)", got)
	}
}

// newHarnessWithProxyTrust wires the harness with a configured
// [proxy.Trust] that admits the 10.0.0.0/8 CIDR. The trust does NOT
// configure a host allowlist, mirroring the legacy compatibility
// posture exercised by [TestAuthorize_TrustedProxy_HonoursXFFForRemoteIP].
func newHarnessWithProxyTrust(t *testing.T) *testHarness {
	t.Helper()
	clock := &fakeClock{now: fixedNow()}
	st := inmem.New(inmem.WithClock(clock))
	registerTestClient(t, st)

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
		Clock: func() time.Time { return clock.now },
	})
	if err != nil {
		t.Fatalf("sessions.NewManager: %v", err)
	}
	csrfKey := make([]byte, 32)
	for i := range csrfKey {
		csrfKey[i] = byte(i + 100)
	}
	signer, _ := csrf.NewSigner(csrfKey)
	allow, _ := csrf.NewAllowlist([]string{"https://op.example.com"})
	trust, err := proxy.NewTrust([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatalf("proxy.NewTrust: %v", err)
	}

	orch := buildTestOrchestrator(t)
	deps := authorizeendpoint.Deps{
		Clients:         st.Clients(),
		Codes:           st.AuthorizationCodes(),
		Grants:          st.Grants(),
		Interactions:    st.Interactions(),
		Sessions:        mgr,
		CookieCodec:     cookieCodec,
		CSRF:            signer,
		Origins:         allow,
		Driver:          interaction.JSONDriver{},
		Authn:           orch,
		AuthorizePath:   "/oidc/auth",
		InteractionPath: "/oidc/interaction",
		Clock:           clock,
		ProxyTrust:      trust,
	}
	return &testHarness{
		handler:        authorizeendpoint.Handler(deps),
		store:          st,
		cookieCodec:    cookieCodec,
		sessionMgr:     mgr,
		csrfSigner:     signer,
		driver:         interaction.JSONDriver{},
		orchestrator:   orch,
		clock:          clock,
		authorizePath:  deps.AuthorizePath,
		interactionPth: deps.InteractionPath,
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
