package endsession_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/backchannel"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/endsession"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// fakeClock returns a fixed wall-clock reading; the handler does not
// consult the clock today, but the field is plumbed to keep the test
// resilient to a future policy change without a refactor.
type fakeClock struct{ now time.Time }

func (f fakeClock) Now() time.Time { return f.now }

// fixedNow is the canonical test clock anchor used across the suite.
// It matches the project's docs' "today" baseline.
func fixedNow() time.Time {
	return time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
}

// harness bundles the handler under test with the supporting
// machinery each test row consumes. Mirrors the pattern in
// internal/authorizeendpoint/authorize_test.go so a maintainer who
// has read either suite can navigate the other.
type harness struct {
	handler        http.Handler
	store          *inmem.Store
	sessionMgr     *sessions.Manager
	signer         josev4.Signer
	clock          *fakeClock
	endSessionPath string
	clientID       string
	postLogoutURI  string
	audit          *endSessionAuditRecorder

	// deps is the dependency set the mounted handler was built from.
	// Rows that need a variant handler (a pairwise subject projector,
	// say) copy it, override the one field they care about, and
	// re-mount through [harness.withSubjectProjector].
	deps endsession.Deps
}

type endSessionAuditRecorder struct {
	events []audit.Event
}

func (r *endSessionAuditRecorder) Emit(_ context.Context, ev audit.Event) {
	r.events = append(r.events, ev)
}

func (r *endSessionAuditRecorder) find(name string) *audit.Event {
	for i := range r.events {
		if r.events[i].Name == name {
			return &r.events[i]
		}
	}
	return nil
}

// harnessOption customises the infrastructure [newHarness] assembles
// before it mounts the handler. The zero set of options is the healthy
// deployment every functional row runs against; a row that needs a
// degraded backend supplies one.
type harnessOption func(*harnessConfig)

// harnessConfig accumulates the option effects.
type harnessConfig struct {
	// wrapSessionStore decorates the session store the session manager
	// is built on, so a row can inject a backend fault the manager and
	// the handler both see through their normal call paths.
	wrapSessionStore func(store.SessionStore) store.SessionStore
}

// withSessionStoreWrapper installs a decorator around the in-memory
// session store.
func withSessionStoreWrapper(fn func(store.SessionStore) store.SessionStore) harnessOption {
	return func(c *harnessConfig) { c.wrapSessionStore = fn }
}

// newHarness builds a handler against fresh in-memory infrastructure
// and registers a single fixture client whose post-logout allowlist
// contains exactly one URI.
func newHarness(t *testing.T, opts ...harnessOption) *harness {
	t.Helper()
	cfg := harnessConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}
	clock := &fakeClock{now: fixedNow()}
	st := inmem.New(inmem.WithClock(clock))

	keyEntry, err := keys.GenerateES256("endsession-active")
	if err != nil {
		t.Fatalf("keys.GenerateES256: %v", err)
	}
	keySet, err := keys.NewSet([]keys.Entry{keyEntry})
	if err != nil {
		t.Fatalf("keys.NewSet: %v", err)
	}
	signer, err := josev4.NewSigner(
		josev4.SigningKey{
			Algorithm: josev4.ES256,
			Key: josev4.JSONWebKey{
				Key:       keyEntry.Signer,
				KeyID:     keyEntry.KeyID,
				Algorithm: string(josev4.ES256),
				Use:       "sig",
			},
		},
		(&josev4.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		t.Fatalf("jose.NewSigner: %v", err)
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
	sessionStore := st.Sessions()
	if cfg.wrapSessionStore != nil {
		sessionStore = cfg.wrapSessionStore(sessionStore)
	}
	mgr, err := sessions.NewManager(sessions.Config{
		Codec: sessCodec,
		Store: sessionStore,
		Clock: clock.Now,
	})
	if err != nil {
		t.Fatalf("sessions.NewManager: %v", err)
	}

	const clientID = "client-end"
	const postLogout = "https://rp.example.com/post-logout"
	if err := st.RegisterClient(context.Background(), &store.Client{
		ID:                      clientID,
		RedirectURIs:            []string{"https://rp.example.com/cb"},
		PostLogoutRedirectURIs:  []string{postLogout},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	auditRecorder := &endSessionAuditRecorder{}
	deps := endsession.Deps{
		Issuer:        "https://op.example.com",
		Clients:       st.Clients(),
		Sessions:      mgr,
		Keys:          keySet,
		Clock:         clock,
		Grants:        st.Grants(),
		AccessTokens:  st.AccessTokens(),
		RefreshTokens: st.RefreshTokens(),
		Audit:         auditRecorder,
	}
	mux := http.NewServeMux()
	const endSessionPath = "/oidc/end_session"
	mux.Handle(endSessionPath, endsession.Handler(deps))

	return &harness{
		handler:        mux,
		store:          st,
		sessionMgr:     mgr,
		signer:         signer,
		clock:          clock,
		endSessionPath: endSessionPath,
		clientID:       clientID,
		postLogoutURI:  postLogout,
		audit:          auditRecorder,
		deps:           deps,
	}
}

// signIDToken serialises a tiny id_token-shaped JWS the handler will
// accept. The default audience equals the harness client ID; the
// builder lets a row override individual claims (tampered aud, far-
// past exp, etc.).
func (h *harness) signIDToken(t *testing.T, build func(claims map[string]any)) string {
	t.Helper()
	claims := map[string]any{
		"iss": "https://op.example.com",
		"sub": "user-1",
		"aud": h.clientID,
		"iat": h.clock.now.Unix(),
		"exp": h.clock.now.Add(time.Hour).Unix(),
	}
	if build != nil {
		build(claims)
	}
	token, err := jwt.Signed(h.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("jwt.Serialize: %v", err)
	}
	return token
}

// stableIDSeq backs nextStableID.
var stableIDSeq atomic.Uint64

// nextStableID mints the kind of caller-decided identifier the
// authorization endpoint derives from its interaction record before it
// persists a completion intent. Only uniqueness within the test binary
// matters here.
func nextStableID(label string) string {
	return label + "-" + strconv.FormatUint(stableIDSeq.Add(1), 10)
}

// establishSession runs the two-step establishment the authorization
// endpoint performs: PlanEstablishment resolves the mode and the exact
// record, then Establish applies it idempotently.
func establishSession(t *testing.T, mgr *sessions.Manager, plan sessions.EstablishPlan) sessions.Outcome {
	t.Helper()
	ctx := context.Background()
	establishment, err := mgr.PlanEstablishment(ctx, plan)
	if err != nil {
		t.Fatalf("PlanEstablishment: %v", err)
	}
	out, err := mgr.Establish(ctx, establishment)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	return out
}

// establishAddAccount joins a further account to the chooser group behind
// cookieValue, the way the chooser prompt's AddAccountURL drives it: the
// current cookie is resolved first so the group it names is the one the new
// account lands in, and the resolved session is what the plan compares the
// incoming subject against.
func establishAddAccount(
	t *testing.T,
	mgr *sessions.Manager,
	cookieValue string,
	login sessions.Login,
	now time.Time,
) sessions.Outcome {
	t.Helper()
	active, err := mgr.Resolve(context.Background(), cookieValue)
	if err != nil {
		t.Fatalf("Resolve current cookie: %v", err)
	}
	return establishSession(t, mgr, sessions.EstablishPlan{
		Active:                   active,
		Login:                    login,
		StableSessionID:          nextStableID("session"),
		StableChooserGroupID:     nextStableID("chooser"),
		ChooserAddAccount:        true,
		ChooserAddAccountGroupID: active.Payload.ChooserGroupID,
		Now:                      now,
	})
}

// issueSession seeds the session store with a brand-new chooser group
// and returns the cookie value plus the underlying session id so the
// test can both attach the cookie to a request and verify post-logout
// store state.
func (h *harness) issueSession(t *testing.T) (cookieValue, sessionID string) {
	t.Helper()
	out := establishSession(t, h.sessionMgr, sessions.EstablishPlan{
		Login: sessions.Login{
			Subject:  "user-1",
			AuthTime: h.clock.now.Add(-time.Minute),
		},
		StableSessionID:      nextStableID("session"),
		StableChooserGroupID: nextStableID("chooser"),
		Now:                  h.clock.now,
	})
	return out.Cookie, out.SessionID
}

// doGET builds and dispatches a GET /end_session with the supplied
// query values. The optional cookieValue installs a session cookie;
// pass an empty string for the no-session paths.
func (h *harness) doGET(t *testing.T, values url.Values, cookieValue string) *http.Response {
	t.Helper()
	target := h.endSessionPath
	if encoded := values.Encode(); encoded != "" {
		target += "?" + encoded
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if cookieValue != "" {
		r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
	}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	return w.Result()
}

// doPOST builds and dispatches a POST /end_session with the supplied
// form values. The cookie attachment shape is identical to [doGET].
func (h *harness) doPOST(t *testing.T, values url.Values, cookieValue string) *http.Response {
	t.Helper()
	r := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		h.endSessionPath,
		strings.NewReader(values.Encode()),
	)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookieValue != "" {
		r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
	}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	return w.Result()
}

// hasClearedSessionCookie reports whether resp carries a Set-Cookie
// header that retires the session profile. The match is conservative:
// we look for the cookie name plus an empty value, which is the
// shape [cookie.Clear] emits. Any other Set-Cookie header is ignored.
func hasClearedSessionCookie(resp *http.Response) bool {
	for _, c := range resp.Cookies() {
		if c.Name == cookie.SessionProfile.Name && c.Value == "" && c.MaxAge < 0 {
			return true
		}
	}
	return false
}

// hasAnySessionCookie reports whether resp carries a Set-Cookie
// header with the session profile name, regardless of value. Used by
// the error-path assertions to confirm the handler did NOT clear the
// cookie on a 400.
func hasAnySessionCookie(resp *http.Response) bool {
	for _, c := range resp.Cookies() {
		if c.Name == cookie.SessionProfile.Name {
			return true
		}
	}
	return false
}

// readBody slurps resp.Body into a string. The helper centralises the
// io.ReadAll + Close boilerplate so the test rows stay focused on
// assertions.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return string(b)
}

// TestHandler_GETLogoutNoHint enforces the H-PROTO-3 CSRF defense:
// a GET /end_session without an id_token_hint MUST render an
// interstitial confirmation page rather than terminating the session
// directly. The page carries the double-submit __Host- CSRF cookie
// and a matching form field; only a follow-up POST with both halves
// of the token actually logs the user out. Without the gate a
// cross-site <img src=...> probe could destroy the session, which
// OIDC RP-Initiated Logout 1.0 §5 (and a corresponding CSRF defense)
// rejects.
func TestHandler_GETLogoutNoHint(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	resp := h.doGET(t, url.Values{}, "")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", resp.StatusCode, body)
	}
	// Without an id_token_hint the OP MUST emit the interstitial
	// confirmation page, not the static logged-out body.
	if !strings.Contains(body, "Confirm sign-out") {
		t.Errorf("body missing confirmation marker: %s", body)
	}
	if !strings.Contains(body, `name="logout_csrf"`) {
		t.Errorf("body missing CSRF token form field: %s", body)
	}
	if !hasConfirmCookie(resp) {
		t.Errorf("confirmation cookie not set; cookies=%v", resp.Cookies())
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type=%q want text/html", got)
	}
	if got := resp.Header.Get("Content-Security-Policy"); got == "" {
		t.Error("Content-Security-Policy header missing")
	} else {
		for _, want := range []string{"form-action 'self'", "sandbox allow-forms allow-same-origin"} {
			if !strings.Contains(got, want) {
				t.Errorf("Content-Security-Policy=%q missing %q", got, want)
			}
		}
	}
	if got := resp.Header.Get("Referrer-Policy"); got != "same-origin" {
		t.Errorf("Referrer-Policy=%q want same-origin", got)
	}
}

// TestHandler_GETLogoutNoHintWithSession confirms the interstitial
// page does NOT terminate the session by itself. The user must POST
// the form to actually log out; the GET MUST leave the session live
// so a hostile cross-site GET cannot defeat the gate by side-effect.
func TestHandler_GETLogoutNoHintWithSession(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, sessionID := h.issueSession(t)

	resp := h.doGET(t, url.Values{}, cookieValue)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	// The interstitial path MUST NOT clear the session cookie or
	// remove the underlying session record; the user has not yet
	// confirmed the logout.
	if hasClearedSessionCookie(resp) {
		t.Errorf("session cookie cleared on GET; CSRF gate bypassed")
	}
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); err != nil {
		t.Errorf("session record terminated by GET interstitial: err=%v", err)
	}
}

// TestHandler_POSTLogoutNoHintCSRF exercises the happy path for the
// hint-less POST: a request that carries both halves of the
// double-submit token (cookie + form field) and a same-origin Origin
// header is admitted, terminates the session, and clears the
// confirmation cookie.
func TestHandler_POSTLogoutNoHintCSRF(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, sessionID := h.issueSession(t)
	getResp := h.doGET(t, url.Values{}, cookieValue)
	defer getResp.Body.Close()
	tok := readConfirmCookie(getResp)
	if tok == "" {
		t.Fatal("interstitial GET did not set the confirmation cookie")
	}

	form := url.Values{"logout_csrf": {tok}}
	addConfirmationGroup(t, h, form, cookieValue)
	r := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		h.endSessionPath,
		strings.NewReader(form.Encode()),
	)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = "op.example.com"
	r.Header.Set("Origin", "https://op.example.com")
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
	r.AddCookie(&http.Cookie{Name: "__Host-oidc_logout_csrf", Value: tok})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if !hasClearedSessionCookie(resp) {
		t.Errorf("session cookie not cleared on confirmed logout")
	}
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("session record still present: err=%v", err)
	}
	ev := h.audit.find("session.destroyed")
	if ev == nil {
		t.Fatalf("session.destroyed not emitted; got=%v", h.audit.events)
	}
	if ev.ActorID != "user-1" {
		t.Errorf("session.destroyed ActorID=%q want user-1", ev.ActorID)
	}
	if ev.SessionID != sessionID {
		t.Errorf("session.destroyed SessionID=%q want %q", ev.SessionID, sessionID)
	}
}

// TestHandler_POSTLogoutNoHintMissingCookie rejects a POST whose
// __Host-oidc_logout_csrf cookie is absent. The form field alone
// MUST NOT pass the gate; without the cookie the request is
// indistinguishable from a forged cross-site submission.
func TestHandler_POSTLogoutNoHintMissingCookie(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, sessionID := h.issueSession(t)
	form := url.Values{"logout_csrf": {"some-token"}}
	r := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		h.endSessionPath,
		strings.NewReader(form.Encode()),
	)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = "op.example.com"
	r.Header.Set("Origin", "https://op.example.com")
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	if hasClearedSessionCookie(resp) {
		t.Errorf("session cookie cleared on rejected POST; CSRF gate bypassed")
	}
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); err != nil {
		t.Errorf("session record terminated by rejected POST: err=%v", err)
	}
}

// TestHandler_POSTLogoutNoHintForeignOrigin rejects a POST whose
// Origin header names a foreign host even when the double-submit
// cookie + token agree. The Origin / Referer check is the
// defense-in-depth gate that catches a SameSite=Lax browser quirk
// where a top-level navigation could leak the cookie; without the
// header check the cookie alone could be replayed cross-site.
func TestHandler_POSTLogoutNoHintForeignOrigin(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, _ := h.issueSession(t)
	getResp := h.doGET(t, url.Values{}, cookieValue)
	defer getResp.Body.Close()
	tok := readConfirmCookie(getResp)
	if tok == "" {
		t.Fatal("interstitial GET did not set the confirmation cookie")
	}

	form := url.Values{"logout_csrf": {tok}}
	addConfirmationGroup(t, h, form, cookieValue)
	r := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		h.endSessionPath,
		strings.NewReader(form.Encode()),
	)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = "op.example.com"
	r.Header.Set("Origin", "https://attacker.example.com")
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
	r.AddCookie(&http.Cookie{Name: "__Host-oidc_logout_csrf", Value: tok})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; foreign Origin must be rejected", resp.StatusCode)
	}
}

func TestHandler_POSTLogoutNoHintNullOriginRejected(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, sessionID := h.issueSession(t)
	getResp := h.doGET(t, url.Values{}, cookieValue)
	defer getResp.Body.Close()
	tok := readConfirmCookie(getResp)
	if tok == "" {
		t.Fatal("interstitial GET did not set the confirmation cookie")
	}

	form := url.Values{"logout_csrf": {tok}}
	addConfirmationGroup(t, h, form, cookieValue)
	r := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		h.endSessionPath,
		strings.NewReader(form.Encode()),
	)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = "op.example.com"
	r.Header.Set("Origin", "null")
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
	r.AddCookie(&http.Cookie{Name: "__Host-oidc_logout_csrf", Value: tok})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; null Origin must be rejected", resp.StatusCode)
	}
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); err != nil {
		t.Errorf("session record terminated by rejected POST: err=%v", err)
	}
}

func TestHandler_POSTLogoutNoHintMissingOriginAndReferer(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, sessionID := h.issueSession(t)
	getResp := h.doGET(t, url.Values{}, cookieValue)
	defer getResp.Body.Close()
	tok := readConfirmCookie(getResp)
	if tok == "" {
		t.Fatal("interstitial GET did not set the confirmation cookie")
	}

	form := url.Values{"logout_csrf": {tok}}
	addConfirmationGroup(t, h, form, cookieValue)
	r := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		h.endSessionPath,
		strings.NewReader(form.Encode()),
	)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = "op.example.com"
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
	r.AddCookie(&http.Cookie{Name: "__Host-oidc_logout_csrf", Value: tok})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; missing Origin/Referer must be rejected", resp.StatusCode)
	}
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); err != nil {
		t.Errorf("session record terminated by rejected POST: err=%v", err)
	}
}

// hasConfirmCookie reports whether resp carries a Set-Cookie header
// that installs the interstitial CSRF cookie. The match is on name
// only because the value is opaque (random per render).
func hasConfirmCookie(resp *http.Response) bool {
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-oidc_logout_csrf" && c.Value != "" {
			return true
		}
	}
	return false
}

// readConfirmCookie returns the value of the interstitial CSRF
// cookie carried by resp, or empty when absent. Used by the POST
// rows so the test does not need to scrape the rendered HTML for
// the token.
func readConfirmCookie(resp *http.Response) string {
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-oidc_logout_csrf" {
			return c.Value
		}
	}
	return ""
}

func TestHandler_RedirectHappyPath(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, sessionID := h.issueSession(t)
	idToken := h.signIDToken(t, nil)

	v := url.Values{}
	v.Set("id_token_hint", idToken)
	v.Set("post_logout_redirect_uri", h.postLogoutURI)
	v.Set("state", "xyz")
	resp := h.doGET(t, v, cookieValue)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Scheme != "https" || loc.Host != "rp.example.com" || loc.Path != "/post-logout" {
		t.Errorf("Location=%q want %s", resp.Header.Get("Location"), h.postLogoutURI)
	}
	if got := loc.Query().Get("state"); got != "xyz" {
		t.Errorf("state=%q want xyz", got)
	}
	if !hasClearedSessionCookie(resp) {
		t.Errorf("session cookie not cleared; cookies=%v", resp.Cookies())
	}
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("session record still present: err=%v", err)
	}
}

func TestHandler_RedirectWithExpiredIDToken(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, _ := h.issueSession(t)
	idToken := h.signIDToken(t, func(c map[string]any) {
		c["iat"] = h.clock.now.Add(-30 * 24 * time.Hour).Unix()
		c["exp"] = h.clock.now.Add(-29 * 24 * time.Hour).Unix()
	})

	v := url.Values{}
	v.Set("id_token_hint", idToken)
	v.Set("post_logout_redirect_uri", h.postLogoutURI)
	resp := h.doGET(t, v, cookieValue)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302; expired id_token must still log out", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != h.postLogoutURI {
		t.Errorf("Location=%q want %q", got, h.postLogoutURI)
	}
}

func TestHandler_RedirectWithoutState(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	idToken := h.signIDToken(t, nil)

	v := url.Values{}
	v.Set("id_token_hint", idToken)
	v.Set("post_logout_redirect_uri", h.postLogoutURI)
	resp := h.doGET(t, v, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != h.postLogoutURI {
		// state absent → no ?state= appended.
		t.Errorf("Location=%q want %q", got, h.postLogoutURI)
	}
}

// TestHandler_IDTokenWrongIssuer rejects an id_token_hint that
// carries a foreign iss claim. The check defends against a token
// signed by a different OP being replayed at this /end_session;
// without it, a token whose kid happens to match an OP key would be
// admitted regardless of the issuing tenant.
func TestHandler_IDTokenWrongIssuer(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, sessionID := h.issueSession(t)
	idToken := h.signIDToken(t, func(c map[string]any) {
		c["iss"] = "https://other-op.example.com"
	})

	v := url.Values{}
	v.Set("id_token_hint", idToken)
	resp := h.doGET(t, v, cookieValue)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", resp.StatusCode, body)
	}
	// The hostile id_token MUST NOT terminate the session.
	if hasClearedSessionCookie(resp) {
		t.Errorf("session cookie cleared on rejected id_token: %v", resp.Cookies())
	}
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); err != nil {
		t.Errorf("session terminated by foreign-issuer id_token: err=%v", err)
	}
}

// TestHandler_IDTokenAZPMismatch rejects an id_token_hint whose azp
// does not appear among aud. The check defends against a stolen
// multi-aud token escaping its azp binding when the OP uses azp to
// pick the requesting client.
func TestHandler_IDTokenAZPMismatch(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	idToken := h.signIDToken(t, func(c map[string]any) {
		c["aud"] = h.clientID
		c["azp"] = "client-not-in-aud"
	})

	v := url.Values{}
	v.Set("id_token_hint", idToken)
	resp := h.doGET(t, v, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 (azp not in aud)", resp.StatusCode)
	}
}

func TestHandler_BadIDTokenSignature(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, sessionID := h.issueSession(t)
	idToken := h.signIDToken(t, nil)
	// Flip a byte in the signature segment. JWS is dot-separated; the
	// signature is the last segment.
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected id_token shape: %s", idToken)
	}
	tampered := []byte(parts[2])
	if tampered[0] == 'A' {
		tampered[0] = 'B'
	} else {
		tampered[0] = 'A'
	}
	parts[2] = string(tampered)
	idToken = strings.Join(parts, ".")

	v := url.Values{}
	v.Set("id_token_hint", idToken)
	v.Set("post_logout_redirect_uri", h.postLogoutURI)
	resp := h.doGET(t, v, cookieValue)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", resp.StatusCode, body)
	}
	if hasAnySessionCookie(resp) {
		t.Errorf("error path must not touch session cookie; cookies=%v", resp.Cookies())
	}
	// The session record must still be live after a hostile request.
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); err != nil {
		t.Errorf("session record terminated by error path: err=%v", err)
	}
}

// TestHandler_PostLogoutLoopbackAnyPortForNativeClient pins L-8: a
// native / public client that registered a fixed loopback
// post_logout_redirect_uri may log out to the same URI on any port, the
// RFC 8252 §7.3 allowance /authorize already grants for redirect_uri. An
// exact-match-only gate would reject the ephemeral-port callback the app
// actually binds.
func TestHandler_PostLogoutLoopbackAnyPortForNativeClient(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	const nativeID = "client-native-logout"
	if err := h.store.RegisterClient(context.Background(), &store.Client{
		ID:                      nativeID,
		RedirectURIs:            []string{"http://127.0.0.1/callback"},
		PostLogoutRedirectURIs:  []string{"http://127.0.0.1/callback"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "none",
		PublicClient:            true,
		ApplicationType:         "native",
	}); err != nil {
		t.Fatalf("RegisterClient(native): %v", err)
	}

	idToken := h.signIDToken(t, func(c map[string]any) { c["aud"] = nativeID })
	v := url.Values{}
	v.Set("id_token_hint", idToken)
	v.Set("client_id", nativeID)
	// Registered without a port; requested on an ephemeral one.
	const requested = "http://127.0.0.1:49152/callback"
	v.Set("post_logout_redirect_uri", requested)

	resp := h.doGET(t, v, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302 (native loopback any-port must match); body=%s", resp.StatusCode, readBody(t, resp))
	}
	if got := resp.Header.Get("Location"); got != requested {
		t.Errorf("Location=%q want %q", got, requested)
	}
}

func TestHandler_UnregisteredPostLogoutURI(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	idToken := h.signIDToken(t, nil)

	v := url.Values{}
	v.Set("id_token_hint", idToken)
	v.Set("post_logout_redirect_uri", "https://attacker.example.com/cb")
	resp := h.doGET(t, v, "")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; body=%s", resp.StatusCode, body)
	}
	// The response MUST be the static error page, never a redirect.
	if got := resp.Header.Get("Location"); got != "" {
		t.Errorf("unexpected Location header: %q", got)
	}
}

func TestHandler_PostLogoutWithoutClient(t *testing.T) {
	t.Parallel()

	h := newHarness(t)

	v := url.Values{}
	v.Set("post_logout_redirect_uri", h.postLogoutURI)
	resp := h.doGET(t, v, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
}

func TestHandler_ClientIDAudMismatch(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	idToken := h.signIDToken(t, func(c map[string]any) {
		c["aud"] = h.clientID
	})

	// Register a second client whose ID we will pass as the parameter
	// so resolveByClientID does not fail with descClientNotFound for
	// the wrong reason.
	const otherID = "client-other"
	if err := h.store.RegisterClient(context.Background(), &store.Client{
		ID:                      otherID,
		RedirectURIs:            []string{"https://rp.example.com/cb"},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}); err != nil {
		t.Fatalf("RegisterClient(other): %v", err)
	}

	v := url.Values{}
	v.Set("id_token_hint", idToken)
	v.Set("client_id", otherID)
	resp := h.doGET(t, v, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
}

func TestHandler_POSTAccepted(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	idToken := h.signIDToken(t, nil)

	v := url.Values{}
	v.Set("id_token_hint", idToken)
	v.Set("post_logout_redirect_uri", h.postLogoutURI)
	v.Set("state", "post-state")
	resp := h.doPOST(t, v, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if got := loc.Query().Get("state"); got != "post-state" {
		t.Errorf("state=%q want post-state", got)
	}
}

// TestHandler_BackchannelFanOut wires a [backchannel.Coordinator]
// into the handler and verifies that a successful logout dispatches
// a Logout Token to every grantee that registered a
// backchannel_logout_uri.
func TestHandler_BackchannelFanOut(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, sessionID := h.issueSession(t)

	const rpClient = "rp-back"
	if err := h.store.RegisterClient(context.Background(), &store.Client{
		ID:                   rpClient,
		BackchannelLogoutURI: "https://rp-back.example/logout",
	}); err != nil {
		t.Fatalf("RegisterClient(rp-back): %v", err)
	}
	now := h.clock.now
	if err := h.store.Grants().Save(context.Background(), &store.Grant{
		ID:        "g-back",
		Subject:   "user-1",
		ClientID:  rpClient,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Grants().Save: %v", err)
	}

	keyEntry, err := keys.GenerateES256("bcc-1")
	if err != nil {
		t.Fatalf("keys.GenerateES256: %v", err)
	}
	var calls atomic.Int32
	var capturedAud string
	var capturedSID bool
	deliver := backchannel.DelivererFunc(func(_ context.Context, target backchannel.Target, token string) error {
		calls.Add(1)
		capturedAud = target.ClientID
		parsed, err := jwt.ParseSigned(token, []josev4.SignatureAlgorithm{josev4.ES256})
		if err != nil {
			t.Errorf("parse logout token: %v", err)
			return err
		}
		claims := map[string]any{}
		if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
			t.Errorf("decode claims: %v", err)
			return err
		}
		_, capturedSID = claims["sid"]
		return nil
	})
	coord, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer:    "https://op.example.com",
		Signing:   backchannel.SigningKey{KeyID: keyEntry.KeyID, Signer: keyEntry.Signer},
		Clients:   h.store.Clients(),
		Grants:    h.store.Grants().(store.GrantClientLister),
		Deliverer: deliver,
	})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}

	deps := endsession.Deps{
		Issuer:      "https://op.example.com",
		Clients:     h.store.Clients(),
		Sessions:    h.sessionMgr,
		Keys:        nil,
		Clock:       h.clock,
		Backchannel: coord,
	}
	mux := http.NewServeMux()
	mux.Handle(h.endSessionPath, endsession.Handler(deps))

	// The hint-less flow now goes GET (interstitial) → POST (confirm).
	getReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, h.endSessionPath, http.NoBody)
	getReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
	getW := httptest.NewRecorder()
	mux.ServeHTTP(getW, getReq)
	getResp := getW.Result()
	tok := readConfirmCookie(getResp)
	getResp.Body.Close()
	if tok == "" {
		t.Fatal("interstitial GET did not set the confirmation cookie")
	}

	form := url.Values{"logout_csrf": {tok}}
	addConfirmationGroup(t, h, form, cookieValue)
	r := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		h.endSessionPath,
		strings.NewReader(form.Encode()),
	)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = "op.example.com"
	r.Header.Set("Origin", "https://op.example.com")
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
	r.AddCookie(&http.Cookie{Name: "__Host-oidc_logout_csrf", Value: tok})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	// The fan-out is detached from the request, so the delivery may
	// still be in flight when the response lands. Draining is what
	// establishes the happens-before edge for the captured values.
	drainFanOut(t, coord)
	if got := calls.Load(); got != 1 {
		t.Fatalf("deliverer called %d times, want 1", got)
	}
	if capturedAud != rpClient {
		t.Errorf("logout-token aud=%q want %q", capturedAud, rpClient)
	}
	if capturedSID {
		t.Errorf("logout-token disclosed unrelated browser sid %q", sessionID)
	}
}

// TestHandler_RevokesAccessTokensOnLogout verifies the access-token
// cascade: when /end_session terminates the session, every
// access-token record bound to a grant the subject still holds is
// marked revoked. The test stops at the registry boundary; the
// follow-on "userinfo returns 401 for a revoked record" path is
// covered by internal/userinfo/handler_test.go's
// enforceRevocationStatus tests, so the two layers together prove
// the FAPI 2.0 SP §5.3.2.2 / OIDC RP-Initiated Logout 1.0 §5
// expectation is honoured.
func TestHandler_RevokesAccessTokensOnLogout(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, _ := h.issueSession(t)

	const grantID = "g-revoke"
	now := h.clock.now
	if err := h.store.Grants().Save(context.Background(), &store.Grant{
		ID:        grantID,
		Subject:   "user-1",
		ClientID:  h.clientID,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Grants().Save: %v", err)
	}
	const jti = "jti-revoke"
	if err := h.store.AccessTokens().Register(context.Background(), store.AccessTokenRecord{
		JTI:       jti,
		GrantID:   grantID,
		Subject:   "user-1",
		ClientID:  h.clientID,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("AccessTokens().Register: %v", err)
	}

	// The hint-less flow needs the interstitial GET → POST to clear
	// the CSRF gate; the cascade fires only after the confirmed POST.
	getResp := h.doGET(t, url.Values{}, cookieValue)
	tok := readConfirmCookie(getResp)
	getResp.Body.Close()
	if tok == "" {
		t.Fatal("interstitial GET did not set the confirmation cookie")
	}
	form := url.Values{"logout_csrf": {tok}}
	addConfirmationGroup(t, h, form, cookieValue)
	r := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		h.endSessionPath,
		strings.NewReader(form.Encode()),
	)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = "op.example.com"
	r.Header.Set("Origin", "https://op.example.com")
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
	r.AddCookie(&http.Cookie{Name: "__Host-oidc_logout_csrf", Value: tok})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}

	rec, err := h.store.AccessTokens().Find(context.Background(), jti)
	if err != nil {
		t.Fatalf("AccessTokens().Find: %v", err)
	}
	if rec == nil {
		t.Fatal("AccessTokens().Find returned nil record")
	}
	if !rec.Revoked {
		t.Errorf("AccessTokenRecord.Revoked=false want true (access-token cascade not wired)")
	}
}

// TestHandler_AccessTokenCascadeNoCascadeWithoutDeps confirms the
// cascade is opt-in: when [endsession.Deps] omits Grants /
// AccessTokens (the embedder skipped the registry wiring), logout
// still terminates the session but leaves the registry alone.
func TestHandler_AccessTokenCascadeNoCascadeWithoutDeps(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, _ := h.issueSession(t)

	const grantID = "g-skip"
	now := h.clock.now
	if err := h.store.Grants().Save(context.Background(), &store.Grant{
		ID:        grantID,
		Subject:   "user-1",
		ClientID:  h.clientID,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Grants().Save: %v", err)
	}
	const jti = "jti-skip"
	if err := h.store.AccessTokens().Register(context.Background(), store.AccessTokenRecord{
		JTI:       jti,
		GrantID:   grantID,
		Subject:   "user-1",
		ClientID:  h.clientID,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("AccessTokens().Register: %v", err)
	}

	deps := endsession.Deps{
		Issuer:   "https://op.example.com",
		Clients:  h.store.Clients(),
		Sessions: h.sessionMgr,
		Clock:    h.clock,
	}
	mux := http.NewServeMux()
	mux.Handle(h.endSessionPath, endsession.Handler(deps))

	// Interstitial GET → confirmed POST so the CSRF gate passes.
	getReq := httptest.NewRequestWithContext(context.Background(), http.MethodGet, h.endSessionPath, http.NoBody)
	getReq.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
	getW := httptest.NewRecorder()
	mux.ServeHTTP(getW, getReq)
	getResp := getW.Result()
	tok := readConfirmCookie(getResp)
	getResp.Body.Close()
	if tok == "" {
		t.Fatal("interstitial GET did not set the confirmation cookie")
	}
	form := url.Values{"logout_csrf": {tok}}
	addConfirmationGroup(t, h, form, cookieValue)
	r := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		h.endSessionPath,
		strings.NewReader(form.Encode()),
	)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = "op.example.com"
	r.Header.Set("Origin", "https://op.example.com")
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
	r.AddCookie(&http.Cookie{Name: "__Host-oidc_logout_csrf", Value: tok})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}

	rec, err := h.store.AccessTokens().Find(context.Background(), jti)
	if err != nil {
		t.Fatalf("AccessTokens().Find: %v", err)
	}
	if rec == nil {
		t.Fatal("AccessTokens().Find returned nil record")
	}
	if rec.Revoked {
		t.Errorf("AccessTokenRecord.Revoked=true want false; cascade fired without Grants/AccessTokens deps")
	}
}

// TestHandler_PostLogoutMalformedFallback covers the L-PROTO-4
// regression guard: when buildPostLogoutRedirect cannot parse the
// pre-registered post_logout_redirect_uri, the handler MUST NOT
// emit the raw value as a Location header. Falling onto the static
// confirmation page closes the latent open-redirect surface that
// would open if a future regression loosened the exact-match
// validatePostLogout rule.
//
// The test drives the fallback by injecting a malformed URI directly
// through the [op/store.Client.PostLogoutRedirectURIs] allowlist; an
// embedder that registered an unparseable URI by mistake hits the
// same path.
func TestHandler_PostLogoutMalformedFallback(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	const malformed = "https://rp.example.com/cb%zz"
	if err := h.store.RegisterClient(context.Background(), &store.Client{
		ID:                      "client-bad-postlogout",
		RedirectURIs:            []string{"https://rp.example.com/cb"},
		PostLogoutRedirectURIs:  []string{malformed},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	idToken := h.signIDToken(t, func(c map[string]any) {
		c["aud"] = "client-bad-postlogout"
	})
	v := url.Values{}
	v.Set("id_token_hint", idToken)
	v.Set("post_logout_redirect_uri", malformed)
	v.Set("state", "x")
	resp := h.doGET(t, v, "")
	defer resp.Body.Close()
	// The malformed URI MUST NOT be echoed as a Location; the
	// handler falls onto the static confirmation page instead.
	if got := resp.Header.Get("Location"); got != "" {
		t.Errorf("Location=%q want empty (malformed URI must not redirect)", got)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 (fallback page)", resp.StatusCode)
	}
}

func TestHandler_MethodNotAllowed(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPut, h.endSessionPath, http.NoBody)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); got == "" {
		t.Error("Allow header missing")
	}
}

func TestHandler_HEAD_AcceptedWhenGETIsSupported(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodHead, h.endSessionPath, http.NoBody)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusMethodNotAllowed {
		t.Fatal("HEAD returned 405")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 interstitial equivalent", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Security-Policy"); !strings.Contains(got, "allow-forms") {
		t.Errorf("Content-Security-Policy=%q missing allow-forms", got)
	}
}

// TestHandler_DuplicateSingleValuedParameter pins the rule that
// /end_session MUST refuse a request that repeats any of the
// single-valued parameters defined by OIDC RP-Initiated Logout 1.0
// §2 (id_token_hint, client_id, post_logout_redirect_uri, state,
// logout_hint, ui_locales) plus the double-submit confirmation
// token field. The check shares the [httpx.FirstDuplicateParameter]
// helper with the token / PAR / CIBA endpoints so the input-shape
// policy is uniform across the whole OP. Both GET and POST paths
// flow through the same gate.
func TestHandler_DuplicateSingleValuedParameter(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		key  string
		v1   string
		v2   string
	}{
		{name: "id_token_hint", key: "id_token_hint", v1: "tok-a", v2: "tok-b"},
		{name: "client_id", key: "client_id", v1: "client-a", v2: "client-b"},
		{name: "post_logout_redirect_uri", key: "post_logout_redirect_uri", v1: "https://rp.example.com/a", v2: "https://rp.example.com/b"},
		{name: "state", key: "state", v1: "s1", v2: "s2"},
		{name: "logout_hint", key: "logout_hint", v1: "h1", v2: "h2"},
		{name: "ui_locales", key: "ui_locales", v1: "en", v2: "ja"},
		{name: "logout_scope", key: "logout_scope", v1: "current", v2: "current"},
		{name: "chooser_group_id", key: "chooser_group_id", v1: "group-a", v2: "group-b"},
	}

	for _, tc := range cases {
		t.Run("GET/"+tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			values := url.Values{}
			values.Add(tc.key, tc.v1)
			values.Add(tc.key, tc.v2)
			resp := h.doGET(t, values, "")
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				body := readBody(t, resp)
				t.Fatalf("status=%d want 400; body=%s", resp.StatusCode, body)
			}
		})
		t.Run("POST/"+tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			values := url.Values{}
			values.Add(tc.key, tc.v1)
			values.Add(tc.key, tc.v2)
			resp := h.doPOST(t, values, "")
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				body := readBody(t, resp)
				t.Fatalf("status=%d want 400; body=%s", resp.StatusCode, body)
			}
		})
	}
}

// TestHandler_DuplicateConfirmTokenRejected pins the rule that the
// double-submit "logout_csrf" form field is also single-valued.
// The audit calls out the confirm-token first-value-wins as the
// same kind of parser-confusion vector as the protocol parameters,
// so the gate fires uniformly across every named field the
// dispatcher reads.
func TestHandler_DuplicateConfirmTokenRejected(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	values := url.Values{}
	values.Add("logout_csrf", "tok-a")
	values.Add("logout_csrf", "tok-b")
	resp := h.doPOST(t, values, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		body := readBody(t, resp)
		t.Fatalf("status=%d want 400; body=%s", resp.StatusCode, body)
	}
}
