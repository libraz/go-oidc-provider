package endsession_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

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
}

// newHarness builds a handler against fresh in-memory infrastructure
// and registers a single fixture client whose post-logout allowlist
// contains exactly one URI.
func newHarness(t *testing.T) *harness {
	t.Helper()
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
	mgr, err := sessions.NewManager(sessions.Config{
		Codec: sessCodec,
		Store: st.Sessions(),
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

	deps := endsession.Deps{
		Issuer:       "https://op.example.com",
		Clients:      st.Clients(),
		Sessions:     mgr,
		Keys:         keySet,
		Clock:        clock,
		Grants:       st.Grants(),
		AccessTokens: st.AccessTokens(),
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

// issueSession seeds the session store with a brand-new chooser group
// and returns the cookie value plus the underlying session id so the
// test can both attach the cookie to a request and verify post-logout
// store state.
func (h *harness) issueSession(t *testing.T) (cookieValue, sessionID string) {
	t.Helper()
	out, err := h.sessionMgr.Issue(context.Background(), sessions.Login{
		Subject:  "user-1",
		AuthTime: h.clock.now.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("sessionMgr.Issue: %v", err)
	}
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

func TestHandler_GETLogoutNoHint(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	resp := h.doGET(t, url.Values{}, "")
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "Signed out") {
		t.Errorf("body missing logged-out marker: %s", body)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Errorf("Content-Type=%q want text/html", got)
	}
	if got := resp.Header.Get("Content-Security-Policy"); got == "" {
		t.Error("Content-Security-Policy header missing")
	}
}

func TestHandler_GETLogoutWithSession(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, sessionID := h.issueSession(t)

	resp := h.doGET(t, url.Values{}, cookieValue)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if !hasClearedSessionCookie(resp) {
		t.Errorf("session cookie not cleared; cookies=%v", resp.Cookies())
	}
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("session record still present: err=%v", err)
	}
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
	var capturedSID string
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
		if sid, _ := claims["sid"].(string); sid != "" {
			capturedSID = sid
		}
		return nil
	})
	coord, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer:    "https://op.example.com",
		Signing:   backchannel.SigningKey{KeyID: keyEntry.KeyID, Signer: keyEntry.Signer},
		Clients:   h.store.Clients(),
		Grants:    h.store.Grants(),
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

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, h.endSessionPath, http.NoBody)
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("deliverer called %d times, want 1", got)
	}
	if capturedAud != rpClient {
		t.Errorf("logout-token aud=%q want %q", capturedAud, rpClient)
	}
	if capturedSID != sessionID {
		t.Errorf("logout-token sid=%q want %q", capturedSID, sessionID)
	}
}

// TestHandler_RevokesAccessTokensOnLogout verifies the ADR 0013
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

	resp := h.doGET(t, url.Values{}, cookieValue)
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
		t.Errorf("AccessTokenRecord.Revoked=false want true (ADR 0013 cascade not wired)")
	}
}

// TestHandler_AccessTokenCascadeNoCascadeWithoutDeps confirms the
// cascade is opt-in: when [endsession.Deps] omits Grants /
// AccessTokens (the embedder skipped ADR 0013 wiring), logout still
// terminates the session but leaves the registry alone.
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
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, h.endSessionPath, http.NoBody)
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
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
