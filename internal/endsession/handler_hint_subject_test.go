package endsession_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/endsession"
	"github.com/libraz/go-oidc-provider/op/store"
)

// withSubjectProjector returns a harness clone whose handler was built
// with the supplied subject projector. Everything else (store, session
// manager, keyset, clock) is shared with the receiver so a row can seed
// state through either value.
func (h *harness) withSubjectProjector(
	t *testing.T,
	fn func(ctx context.Context, raw string, client *store.Client) (string, error),
) *harness {
	t.Helper()
	deps := h.deps
	deps.SubjectProjector = fn
	mux := http.NewServeMux()
	mux.Handle(h.endSessionPath, endsession.Handler(deps))
	clone := *h
	clone.deps = deps
	clone.handler = mux
	return &clone
}

// pairwiseProjector mimics the shape of a pairwise subject generator:
// a deterministic per-client digest of the OP-internal subject. The
// exact derivation is irrelevant to the tests — what matters is that
// the projected value differs per client and never equals the raw
// subject the session stores.
func pairwiseProjector(_ context.Context, raw string, client *store.Client) (string, error) {
	id := ""
	if client != nil {
		id = client.ID
	}
	sum := sha256.Sum256([]byte(id + ":" + raw))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// confirmPOST dispatches a same-origin POST /end_session carrying the
// supplied form, session cookie, and double-submit CSRF cookie. An
// empty cookie argument omits the corresponding header.
func confirmPOST(t *testing.T, h *harness, form url.Values, sessionCookie, csrf string) *http.Response {
	t.Helper()
	r := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		h.endSessionPath,
		strings.NewReader(form.Encode()),
	)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = "op.example.com"
	r.Header.Set("Origin", "https://op.example.com")
	if sessionCookie != "" {
		r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessionCookie})
	}
	if csrf != "" {
		r.AddCookie(&http.Cookie{Name: "__Host-oidc_logout_csrf", Value: csrf})
	}
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	return w.Result()
}

// seedGrantWithAccessToken registers one grant for subject plus a
// shadow access-token row under it, and returns the jti so a row can
// assert whether the logout cascade fired.
func seedGrantWithAccessToken(t *testing.T, h *harness, grantID, jti, subject string) {
	t.Helper()
	now := h.clock.now
	if err := h.store.Grants().Save(context.Background(), &store.Grant{
		ID:        grantID,
		Subject:   subject,
		ClientID:  h.clientID,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Grants().Save: %v", err)
	}
	if err := h.store.AccessTokens().Register(context.Background(), store.AccessTokenRecord{
		JTI:       jti,
		GrantID:   grantID,
		Subject:   subject,
		ClientID:  h.clientID,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("AccessTokens().Register: %v", err)
	}
}

// accessTokenRevoked reports the Revoked flag of the shadow row jti.
func accessTokenRevoked(t *testing.T, h *harness, jti string) bool {
	t.Helper()
	rec, err := h.store.AccessTokens().Find(context.Background(), jti)
	if err != nil {
		t.Fatalf("AccessTokens().Find: %v", err)
	}
	if rec == nil {
		t.Fatal("AccessTokens().Find returned nil record")
	}
	return rec.Revoked
}

// TestHandler_ForeignSubjectHintDoesNotTerminateSession pins the
// central rule of the hint gate: an id_token_hint identifies the
// requesting client, NOT the browser presenting it. An attacker who
// holds an account at the same OP can mint a perfectly valid hint for
// their own subject and embed it in a cross-site <img src=...>; if the
// hint alone skipped the confirmation gate, every visitor would be
// signed out and have their access tokens revoked. The victim's
// session, session cookie, and access tokens MUST all survive, and the
// OP MUST fall back to the interstitial confirmation page.
func TestHandler_ForeignSubjectHintDoesNotTerminateSession(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, sessionID := h.issueSession(t) // subject "user-1"
	seedGrantWithAccessToken(t, h, "g-foreign", "jti-foreign", "user-1")

	// A valid, freshly signed hint — for somebody else's subject.
	hint := h.signIDToken(t, func(c map[string]any) { c["sub"] = "attacker-9" })
	v := url.Values{}
	v.Set("id_token_hint", hint)
	v.Set("post_logout_redirect_uri", h.postLogoutURI)

	resp := h.doGET(t, v, cookieValue)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 (confirmation page); body=%s", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Location"); got != "" {
		t.Errorf("Location=%q want empty; foreign hint must not redirect", got)
	}
	if !strings.Contains(body, "Confirm sign-out") {
		t.Errorf("body missing confirmation marker: %s", body)
	}
	if hasClearedSessionCookie(resp) {
		t.Errorf("session cookie cleared by a foreign subject's hint; cookies=%v", resp.Cookies())
	}
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); err != nil {
		t.Errorf("session terminated by a foreign subject's hint: err=%v", err)
	}
	if accessTokenRevoked(t, h, "jti-foreign") {
		t.Error("access token revoked by a foreign subject's hint")
	}
}

// TestHandler_ForeignSubjectHintPOSTRejected covers the POST arm of
// the same attack: a cross-site form submission carrying the
// attacker's hint has no double-submit CSRF token, so it fails closed
// with a 400 and leaves the session intact.
func TestHandler_ForeignSubjectHintPOSTRejected(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, sessionID := h.issueSession(t)
	hint := h.signIDToken(t, func(c map[string]any) { c["sub"] = "attacker-9" })

	form := url.Values{}
	form.Set("id_token_hint", hint)
	form.Set("post_logout_redirect_uri", h.postLogoutURI)
	resp := confirmPOST(t, h, form, cookieValue, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	if hasClearedSessionCookie(resp) {
		t.Errorf("session cookie cleared on rejected POST; cookies=%v", resp.Cookies())
	}
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); err != nil {
		t.Errorf("session terminated by a foreign subject's hint POST: err=%v", err)
	}
}

// TestHandler_MatchingSubjectHintTerminatesImmediately pins the other
// side of the gate: when the hint names the subject the session cookie
// authenticates, the request carries genuine proof of intent and the
// OP signs out directly — no interstitial, session record gone,
// cascade fired.
func TestHandler_MatchingSubjectHintTerminatesImmediately(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, sessionID := h.issueSession(t)
	seedGrantWithAccessToken(t, h, "g-match", "jti-match", "user-1")

	hint := h.signIDToken(t, nil) // sub == "user-1"
	v := url.Values{}
	v.Set("id_token_hint", hint)
	v.Set("post_logout_redirect_uri", h.postLogoutURI)

	resp := h.doGET(t, v, cookieValue)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	if !hasClearedSessionCookie(resp) {
		t.Error("session cookie not cleared on a matching-subject logout")
	}
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("session record still present: err=%v", err)
	}
	if !accessTokenRevoked(t, h, "jti-match") {
		t.Error("access-token cascade did not fire on a matching-subject logout")
	}
}

// TestHandler_HintWithoutSubjectFallsBackToConfirmation pins the
// fail-secure default for a hint that carries no "sub" at all: the OP
// cannot prove the token belongs to this session, so it asks.
func TestHandler_HintWithoutSubjectFallsBackToConfirmation(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, sessionID := h.issueSession(t)
	hint := h.signIDToken(t, func(c map[string]any) { delete(c, "sub") })

	v := url.Values{}
	v.Set("id_token_hint", hint)
	resp := h.doGET(t, v, cookieValue)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200; body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "Confirm sign-out") {
		t.Errorf("body missing confirmation marker: %s", body)
	}
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); err != nil {
		t.Errorf("session terminated by a subject-less hint: err=%v", err)
	}
}

// TestHandler_HintWithoutSessionStillRedirects pins the no-session
// admission: with no resolvable session there is nothing to destroy,
// so a valid hint keeps producing the post-logout redirect the RP
// asked for rather than an unexpected confirmation page.
func TestHandler_HintWithoutSessionStillRedirects(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	hint := h.signIDToken(t, func(c map[string]any) { c["sub"] = "somebody-else" })
	v := url.Values{}
	v.Set("id_token_hint", hint)
	v.Set("post_logout_redirect_uri", h.postLogoutURI)

	resp := h.doGET(t, v, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	if got := resp.Header.Get("Location"); got != h.postLogoutURI {
		t.Errorf("Location=%q want %q", got, h.postLogoutURI)
	}
}

// TestHandler_ClientIDConfirmationRoundTrip walks the flow an RP that
// does not hold an ID Token uses: GET with client_id +
// post_logout_redirect_uri renders the confirmation page, and the
// POST that page submits terminates the session and redirects. The row
// pins the hidden client_id field explicitly — without it the POST
// arrives with no resolvable client and the OP rejects its own form
// with "post_logout_redirect_uri requires a client".
func TestHandler_ClientIDConfirmationRoundTrip(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, sessionID := h.issueSession(t)

	v := url.Values{}
	v.Set("client_id", h.clientID)
	v.Set("post_logout_redirect_uri", h.postLogoutURI)
	v.Set("state", "round-trip")
	getResp := h.doGET(t, v, cookieValue)
	body := readBody(t, getResp)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET status=%d want 200; body=%s", getResp.StatusCode, body)
	}
	if !strings.Contains(body, `name="client_id" value="`+h.clientID+`"`) {
		t.Errorf("confirmation form dropped client_id: %s", body)
	}
	// The action is relative and query-less so the POST lands back on
	// this endpoint without re-sending the parameters the hidden
	// fields already carry.
	if !strings.Contains(body, `action="./end_session"`) {
		t.Errorf("confirmation form action does not point back at the endpoint: %s", body)
	}
	tok := readConfirmCookie(getResp)
	if tok == "" {
		t.Fatal("interstitial GET did not set the confirmation cookie")
	}

	form := url.Values{}
	form.Set("client_id", h.clientID)
	form.Set("post_logout_redirect_uri", h.postLogoutURI)
	form.Set("state", "round-trip")
	form.Set("logout_csrf", tok)
	postResp := confirmPOST(t, h, form, cookieValue, tok)
	defer postResp.Body.Close()

	if postResp.StatusCode != http.StatusFound {
		t.Fatalf("POST status=%d want 302; body=%s", postResp.StatusCode, readBody(t, postResp))
	}
	loc, err := url.Parse(postResp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	if loc.Scheme != "https" || loc.Host != "rp.example.com" || loc.Path != "/post-logout" {
		t.Errorf("Location=%q want %q", postResp.Header.Get("Location"), h.postLogoutURI)
	}
	if got := loc.Query().Get("state"); got != "round-trip" {
		t.Errorf("state=%q want round-trip", got)
	}
	if !hasClearedSessionCookie(postResp) {
		t.Error("session cookie not cleared on the confirmed POST")
	}
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("session record still present after the confirmed POST: err=%v", err)
	}
}

// TestHandler_PairwiseSubjectHintMatchesProjectedSession pins the
// pairwise arm of the comparison: the session stores the OP-internal
// subject while the id_token carries the per-client projection, so the
// gate must compare in the projected space. A hint carrying the
// correctly projected value logs the user out immediately.
func TestHandler_PairwiseSubjectHintMatchesProjectedSession(t *testing.T) {
	t.Parallel()

	base := newHarness(t)
	h := base.withSubjectProjector(t, pairwiseProjector)
	cookieValue, sessionID := h.issueSession(t)

	client, err := h.store.Clients().GetClient(context.Background(), h.clientID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	projected, err := pairwiseProjector(context.Background(), "user-1", client)
	if err != nil {
		t.Fatalf("pairwiseProjector: %v", err)
	}
	hint := h.signIDToken(t, func(c map[string]any) { c["sub"] = projected })

	v := url.Values{}
	v.Set("id_token_hint", hint)
	v.Set("post_logout_redirect_uri", h.postLogoutURI)
	resp := h.doGET(t, v, cookieValue)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302; pairwise sub must match the projected session subject", resp.StatusCode)
	}
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("session record still present: err=%v", err)
	}
}

// TestHandler_PairwiseSubjectHintRejectsRawSubject is the companion
// negative: under a pairwise projector the OP-internal subject is NOT
// a value any id_token carries, so a hint that presents it has not
// proven anything about this browser and falls back to the
// confirmation page.
func TestHandler_PairwiseSubjectHintRejectsRawSubject(t *testing.T) {
	t.Parallel()

	base := newHarness(t)
	h := base.withSubjectProjector(t, pairwiseProjector)
	cookieValue, sessionID := h.issueSession(t)

	hint := h.signIDToken(t, nil) // sub == the raw "user-1"
	v := url.Values{}
	v.Set("id_token_hint", hint)
	v.Set("post_logout_redirect_uri", h.postLogoutURI)
	resp := h.doGET(t, v, cookieValue)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 (confirmation page); body=%s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "Confirm sign-out") {
		t.Errorf("body missing confirmation marker: %s", body)
	}
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); err != nil {
		t.Errorf("session terminated by an unprojected subject: err=%v", err)
	}
}

// TestHandler_ProjectorFailureFallsBackToConfirmation pins the
// fail-secure branch for a projector that errors: the OP cannot prove
// the hint matches, so it asks instead of signing the user out.
func TestHandler_ProjectorFailureFallsBackToConfirmation(t *testing.T) {
	t.Parallel()

	base := newHarness(t)
	boom := errors.New("projector unavailable")
	h := base.withSubjectProjector(t, func(context.Context, string, *store.Client) (string, error) {
		return "", boom
	})
	cookieValue, sessionID := h.issueSession(t)

	hint := h.signIDToken(t, nil)
	v := url.Values{}
	v.Set("id_token_hint", hint)
	resp := h.doGET(t, v, cookieValue)
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 (confirmation page); body=%s", resp.StatusCode, body)
	}
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); err != nil {
		t.Errorf("session terminated despite an unusable projection: err=%v", err)
	}
}
