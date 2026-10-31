package authorizeendpoint

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
)

// resolveSession reads the __Host-oidc_session cookie and asks the manager
// to resolve it. A missing cookie yields (nil, nil). Cookie failures are
// returned to the caller so it can clear the cookie when appropriate.
func resolveSession(w http.ResponseWriter, r *http.Request, deps resolved) (*sessions.Active, error) {
	active, err := resolveSessionWithoutTouch(r, deps)
	if err != nil || active == nil {
		return active, err
	}
	touch, err := deps.Sessions.TouchAndReissue(r.Context(), active)
	if err != nil {
		return nil, err
	}
	// TouchAndReissue refreshes the store row after Resolve returned its
	// snapshot. Keep the in-memory view aligned for decision paths that
	// carry Active into a later establishment plan.
	now := deps.now().UTC()
	active.Session.ExpiresAt = touch.ExpiresAt
	active.Session.UpdatedAt = touch.UpdatedAt
	if w != nil && sessionCookieNeedsRefresh(active.Payload, now) {
		if err := setSessionCookie(w, touch.Cookie, touch.ExpiresAt, now); err != nil {
			return nil, err
		}
	}
	return active, nil
}

// sessionCookieRefreshInterval is how much of a session cookie's browser
// lifetime must elapse before a request that only read the session
// re-seals it.
const sessionCookieRefreshInterval = 24 * time.Hour

// sessionCookieNeedsRefresh reports whether re-sealing the cookie buys
// the browser anything.
//
// A request that merely read the session writes back the selection it
// observed when it started. If another tab switched accounts in the
// meantime, that write restores the older account silently, and the next
// prompt=none request mints for a subject the user has already left. So
// re-sealing has to be worth the risk: either the payload carries no
// issuance stamp, in which case nothing can be reasoned about and the
// cookie is refreshed, or its browser Max-Age window has aged far enough
// that extending it matters.
//
// The server-side touch stays unconditional — it extends the idle
// lifetime without writing a selection back, so it cannot roll one back.
// Only the Set-Cookie is held back.
func sessionCookieNeedsRefresh(p sessions.Payload, now time.Time) bool {
	if p.IssuedAt == 0 {
		return true
	}
	return now.Sub(time.Unix(p.IssuedAt, 0).UTC()) >= sessionCookieRefreshInterval
}

// resolveSessionWithoutTouch validates and loads the browser session without
// extending its idle lifetime. Completion first needs a stable snapshot to
// plan reuse, rotation, or chooser switching; the terminal path then touches
// only the session that will remain current and emits the matching cookie.
func resolveSessionWithoutTouch(r *http.Request, deps resolved) (*sessions.Active, error) {
	c, err := r.Cookie(cookie.SessionProfile.Name)
	if err != nil {
		// http.ErrNoCookie is the only documented error from r.Cookie;
		// any return value here is treated as "no session" because we
		// cannot decode what the browser did not send.
		return nil, nil //nolint:nilerr,nilnil // documented "no session" sentinel
	}
	if c == nil || c.Value == "" {
		return nil, nil //nolint:nilnil // documented "no session" sentinel
	}
	active, err := deps.Sessions.Resolve(r.Context(), c.Value)
	if err != nil {
		return nil, err
	}
	return active, nil
}

// setSessionCookie writes the browser-session cookie through
// [cookie.SetSession], capping its lifetime at the server-side expiry. An
// elapsed expiry is reported as [sessions.ErrCurrentSessionExpired] so the
// caller treats it like any other expired session.
func setSessionCookie(w http.ResponseWriter, value string, expiresAt, now time.Time) error {
	err := cookie.SetSession(w, value, expiresAt, now)
	if errors.Is(err, cookie.ErrSessionExpired) {
		return sessions.ErrCurrentSessionExpired
	}
	if err != nil {
		return fmt.Errorf("authorizeendpoint: build session cookie: %w", err)
	}
	return nil
}
