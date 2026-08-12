package endsession_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/store"
)

// confirmScope performs the interstitial GET followed by the same-origin
// confirmation POST. An absent scope remains absent on the POST; current is
// copied explicitly through the hidden form field.
func confirmScope(t *testing.T, h *harness, query url.Values, sessionCookie string) *http.Response {
	t.Helper()
	get := h.doGET(t, query, sessionCookie)
	token := readConfirmCookie(get)
	body := readBody(t, get)
	if token == "" {
		t.Fatalf("confirmation GET did not set CSRF cookie; body=%s", body)
	}
	form := url.Values{"logout_csrf": {token}}
	for key, values := range query {
		for _, value := range values {
			form.Add(key, value)
		}
	}
	addConfirmationGroup(t, h, form, sessionCookie)
	r := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		h.endSessionPath,
		strings.NewReader(form.Encode()),
	)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://op.example.com")
	r.Host = "op.example.com"
	if sessionCookie != "" {
		r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessionCookie})
	}
	r.AddCookie(&http.Cookie{Name: cookie.LogoutCSRFProfile.Name, Value: token})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	return w.Result()
}

func addConfirmationGroup(t *testing.T, h *harness, form url.Values, sessionCookie string) {
	t.Helper()
	if sessionCookie == "" {
		return
	}
	active, err := h.sessionMgr.Resolve(context.Background(), sessionCookie)
	if err != nil {
		t.Fatalf("Resolve confirmation session: %v", err)
	}
	scope := form.Get("logout_scope")
	if scope == "" {
		scope = "all"
	}
	form.Set("logout_scope_fingerprint", scope)
	form.Set("chooser_group_id", active.Payload.ChooserGroupID)
}

func sessionCookieFromResponse(resp *http.Response) string {
	for _, c := range resp.Cookies() {
		if c.Name == cookie.SessionProfile.Name && c.Value != "" {
			return c.Value
		}
	}
	return ""
}

func addSiblingSession(t *testing.T, h *harness, cookieValue string) (string, string) {
	t.Helper()
	active, err := h.sessionMgr.Resolve(context.Background(), cookieValue)
	if err != nil {
		t.Fatalf("Resolve initial session: %v", err)
	}
	out, err := h.sessionMgr.AddAccount(context.Background(), active.Payload.ChooserGroupID, sessions.Login{
		Subject:  "user-2",
		AuthTime: h.clock.now,
	})
	if err != nil {
		t.Fatalf("AddAccount: %v", err)
	}
	return out.Cookie, out.SessionID
}

func TestHandler_LogoutScopeDefaultIsChooserGroupWide(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	firstCookie, firstID := h.issueSession(t)
	activeCookie, secondID := addSiblingSession(t, h, firstCookie)
	resp := confirmScope(t, h, url.Values{}, activeCookie)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if !hasClearedSessionCookie(resp) {
		t.Fatalf("group-wide logout did not clear session cookie: %v", resp.Cookies())
	}
	for _, id := range []string{firstID, secondID} {
		if _, err := h.store.Sessions().Find(context.Background(), id); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("session %s remains after default group logout: %v", id, err)
		}
	}
}

func TestHandler_LogoutScopeConfirmationExplainsScope(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		query url.Values
		want  string
	}{
		{name: "default", query: url.Values{}, want: "all browser accounts"},
		{name: "current", query: url.Values{"logout_scope": {"current"}}, want: "this account"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			cookieValue, _ := h.issueSession(t)
			resp := h.doGET(t, tc.query, cookieValue)
			body := readBody(t, resp)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, body)
			}
			if !strings.Contains(body, tc.want) {
				t.Fatalf("confirmation body missing %q: %s", tc.want, body)
			}
		})
	}
}

func TestHandler_LogoutScopeRevokesRefreshChain(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, _ := h.issueSession(t)
	now := h.clock.now
	const grantID = "grant-logout-scope-refresh"
	if err := h.store.Grants().Save(context.Background(), &store.Grant{
		ID:        grantID,
		Subject:   "user-1",
		ClientID:  h.clientID,
		Scope:     []string{"openid"},
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("Grants().Save: %v", err)
	}
	const refreshID = "refresh-logout-scope"
	if err := h.store.RefreshTokens().Save(context.Background(), &store.RefreshToken{
		ID:        refreshID,
		ClientID:  h.clientID,
		Subject:   "user-1",
		GrantID:   grantID,
		Scope:     []string{"openid"},
		ExpiresAt: now.Add(time.Hour),
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("RefreshTokens().Save: %v", err)
	}

	resp := confirmScope(t, h, url.Values{}, cookieValue)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	revoked, err := h.store.RefreshTokens().Find(context.Background(), refreshID)
	if err != nil {
		t.Fatalf("RefreshTokens().Find: %v", err)
	}
	if !revoked.Revoked {
		t.Fatal("refresh chain remains live after group logout")
	}
}

func TestHandler_LogoutScopeCurrentRemovesOnlyActiveAndRebinds(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	firstCookie, firstID := h.issueSession(t)
	activeCookie, secondID := addSiblingSession(t, h, firstCookie)
	resp := confirmScope(t, h, url.Values{"logout_scope": {"current"}}, activeCookie)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if hasClearedSessionCookie(resp) {
		t.Fatalf("current logout cleared cookie despite surviving sibling: %v", resp.Cookies())
	}
	rebound := sessionCookieFromResponse(resp)
	if rebound == "" {
		t.Fatalf("current logout did not issue rebound session cookie: %v", resp.Cookies())
	}
	active, err := h.sessionMgr.Resolve(context.Background(), rebound)
	if err != nil {
		t.Fatalf("Resolve rebound cookie: %v", err)
	}
	if active.Session.ID != firstID {
		t.Errorf("rebound session=%q want surviving %q", active.Session.ID, firstID)
	}
	if _, err := h.store.Sessions().Find(context.Background(), secondID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("active session remains after current logout: %v", err)
	}
	if _, err := h.store.Sessions().Find(context.Background(), firstID); err != nil {
		t.Errorf("sibling removed by current logout: %v", err)
	}
}

func TestHandler_LogoutScopeRejectsUnknownAndEmpty(t *testing.T) {
	t.Parallel()

	for _, scope := range []string{"", "all", "group", " current"} {
		t.Run(scope, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			cookieValue, sessionID := h.issueSession(t)
			resp := h.doGET(t, url.Values{"logout_scope": {scope}}, cookieValue)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("scope %q status=%d want 400", scope, resp.StatusCode)
			}
			if _, err := h.store.Sessions().Find(context.Background(), sessionID); err != nil {
				t.Fatalf("scope validation mutated session: %v", err)
			}
		})
	}
}

func TestHandler_ConfirmationFingerprintBindsChooserGroup(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, sessionID := h.issueSession(t)
	get := h.doGET(t, url.Values{}, cookieValue)
	defer get.Body.Close()
	token := readConfirmCookie(get)
	_ = readBody(t, get)
	form := url.Values{
		"logout_csrf":              {token},
		"logout_scope_fingerprint": {"all"},
		"chooser_group_id":         {"different-group"},
	}
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, h.endSessionPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://op.example.com")
	r.Host = "op.example.com"
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
	r.AddCookie(&http.Cookie{Name: cookie.LogoutCSRFProfile.Name, Value: token})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); err != nil {
		t.Fatalf("confirmation fingerprint failure mutated session: %v", err)
	}
}

func TestHandler_ConfirmationFingerprintBindsLogoutScope(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	cookieValue, sessionID := h.issueSession(t)
	get := h.doGET(t, url.Values{}, cookieValue)
	defer get.Body.Close()
	token := readConfirmCookie(get)
	_ = readBody(t, get)
	form := url.Values{"logout_csrf": {token}}
	addConfirmationGroup(t, h, form, cookieValue)
	form.Set("logout_scope_fingerprint", "current")
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, h.endSessionPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://op.example.com")
	r.Host = "op.example.com"
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
	r.AddCookie(&http.Cookie{Name: cookie.LogoutCSRFProfile.Name, Value: token})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	if _, err := h.store.Sessions().Find(context.Background(), sessionID); err != nil {
		t.Fatalf("scope fingerprint failure mutated session: %v", err)
	}
}
