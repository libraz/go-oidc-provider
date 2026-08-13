package endsession_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/op/store"
)

// reboundSessionCookie returns the Set-Cookie entry that re-seals the
// session profile, or nil when the response carries no such header. A
// cleared cookie (empty value) is not a rebind and is reported as absent.
func reboundSessionCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == cookie.SessionProfile.Name && c.Value != "" {
			return c
		}
	}
	return nil
}

// shortenSession moves a session's server-side expiry to now + remaining
// so a row can describe how much lifetime the surviving chooser sibling
// has left when /end_session rebinds the browser to it.
func shortenSession(t *testing.T, h *harness, sessionID string, remaining time.Duration) {
	t.Helper()
	now := h.clock.now
	if err := h.store.Sessions().Touch(context.Background(), sessionID, now.Add(remaining), now); err != nil {
		t.Fatalf("Sessions().Touch: %v", err)
	}
}

// TestHandler_LogoutScopeCurrentCapsRebindToSiblingLifetime pins the
// browser lifetime of the cookie /end_session rebinds to a surviving
// chooser sibling.
//
// The cookie is the browser's only handle on the session, and the OP
// stops honouring that handle the moment the session's server-side
// expiry passes. A Max-Age longer than the remaining lifetime therefore
// buys nothing and costs something: the browser keeps re-presenting a
// value that is already dead, which is one more window in which a copy
// of the cookie can be replayed, and one more instance of the OP's own
// idle policy being contradicted by what it told the browser.
//
// The sub-second row is the one a careless implementation gets wrong.
// Max-Age is expressed in whole seconds, so truncating a positive
// remainder yields Max-Age=0 — which is not "expired" but "session
// cookie", i.e. a cookie that outlives the session until the browser is
// closed.
func TestHandler_LogoutScopeCurrentCapsRebindToSiblingLifetime(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name       string
		remaining  time.Duration
		wantMaxAge int
	}{
		{name: "capped to the sibling's remaining lifetime", remaining: 90 * time.Second, wantMaxAge: 90},
		{name: "positive sub-second remainder rounds up", remaining: 1500 * time.Millisecond, wantMaxAge: 2},
		{
			name:       "lifetime beyond the profile keeps the profile ceiling",
			remaining:  30 * 24 * time.Hour,
			wantMaxAge: int(cookie.SessionProfile.MaxAge.Seconds()),
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t)
			firstCookie, firstID := h.issueSession(t)
			activeCookie, _ := addSiblingSession(t, h, firstCookie)
			shortenSession(t, h, firstID, row.remaining)

			resp := confirmScope(t, h, url.Values{"logout_scope": {"current"}}, activeCookie)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status=%d want 200", resp.StatusCode)
			}
			rebound := reboundSessionCookie(resp)
			if rebound == nil {
				t.Fatalf("no rebound session cookie issued; cookies=%v", resp.Cookies())
			}
			if rebound.MaxAge != row.wantMaxAge {
				t.Errorf("Max-Age=%d want %d; the browser keeps presenting the session cookie for %ds "+
					"while the session itself lives %s",
					rebound.MaxAge, row.wantMaxAge, rebound.MaxAge, row.remaining)
			}
		})
	}
}

// elapsedGroupSessionStore reports every chooser-group member as already
// past its server-side expiry, without touching the direct reads the
// active session resolves through. It is how a real deployment reaches
// this state: the rows the group listing returns were live when the
// request entered the flow and expired while it ran.
type elapsedGroupSessionStore struct {
	store.SessionStore
	now time.Time
}

func (s *elapsedGroupSessionStore) ListByChooserGroup(ctx context.Context, groupID string) ([]*store.Session, error) {
	rows, err := s.SessionStore.ListByChooserGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		row.ExpiresAt = s.now.Add(-time.Second)
	}
	return rows, nil
}

// TestHandler_LogoutScopeCurrentClearsWhenSiblingLifetimeElapsed covers
// the boundary the cap cannot express. A sibling with nothing left is not
// a cookie with a very small Max-Age: RFC 6265 §5.2.2 reads Max-Age=0 as
// "expire now", but a negative remaining lifetime rounded to any
// non-negative number would hand the browser a value the OP will refuse.
// The only correct answer is to clear the cookie, so the next request
// arrives without a session rather than with a rejected one.
func TestHandler_LogoutScopeCurrentClearsWhenSiblingLifetimeElapsed(t *testing.T) {
	t.Parallel()

	h := newHarness(t, withSessionStoreWrapper(func(s store.SessionStore) store.SessionStore {
		return &elapsedGroupSessionStore{SessionStore: s, now: fixedNow()}
	}))
	firstCookie, _ := h.issueSession(t)
	activeCookie, _ := addSiblingSession(t, h, firstCookie)

	resp := confirmScope(t, h, url.Values{"logout_scope": {"current"}}, activeCookie)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if rebound := reboundSessionCookie(resp); rebound != nil {
		t.Errorf("rebound cookie issued with Max-Age=%d for a sibling whose lifetime has elapsed",
			rebound.MaxAge)
	}
	if !hasClearedSessionCookie(resp) {
		t.Errorf("session cookie not cleared; cookies=%v", resp.Cookies())
	}
}
