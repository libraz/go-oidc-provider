package cookie_test

import (
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/cookie"
)

// buildSessionNow is the fixed clock reading the rows measure against.
func buildSessionNow() time.Time {
	return time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
}

// TestBuildSession_CapsMaxAgeAtRemainingLifetime pins the arithmetic
// every exit path that re-seals the session cookie depends on.
//
// The browser stops being able to use the cookie when the session's
// server-side expiry passes, so a Max-Age beyond that point only extends
// how long a copy of the cookie is worth stealing. The zero-expiry row
// is the deliberate exception: a caller that knows of no server-side
// bound must not have one invented for it.
func TestBuildSession_CapsMaxAgeAtRemainingLifetime(t *testing.T) {
	t.Parallel()

	now := buildSessionNow()
	profileSeconds := int(cookie.SessionProfile.MaxAge.Seconds())
	rows := []struct {
		name       string
		expiresAt  time.Time
		wantMaxAge int
	}{
		{name: "no server-side bound keeps the profile lifetime", wantMaxAge: profileSeconds},
		{
			name:       "expiry beyond the profile keeps the profile lifetime",
			expiresAt:  now.Add(30 * 24 * time.Hour),
			wantMaxAge: profileSeconds,
		},
		{name: "shorter expiry caps the cookie", expiresAt: now.Add(90 * time.Second), wantMaxAge: 90},
		{
			// Truncating this to zero would emit a browser-session
			// cookie, which lives until the browser closes rather than
			// for the fraction of a second that is actually left.
			name:       "positive sub-second remainder rounds up",
			expiresAt:  now.Add(1500 * time.Millisecond),
			wantMaxAge: 2,
		},
		{name: "one whole second stays one second", expiresAt: now.Add(time.Second), wantMaxAge: 1},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			c, err := cookie.BuildSession("sealed-payload", row.expiresAt, now)
			if err != nil {
				t.Fatalf("BuildSession: %v", err)
			}
			if c.MaxAge != row.wantMaxAge {
				t.Errorf("Max-Age=%d want %d", c.MaxAge, row.wantMaxAge)
			}
			if c.Name != cookie.SessionProfile.Name {
				t.Errorf("Name=%q want %q", c.Name, cookie.SessionProfile.Name)
			}
			if c.Value != "sealed-payload" {
				t.Errorf("Value=%q want the payload verbatim", c.Value)
			}
		})
	}
}

// TestBuildSession_RefusesElapsedLifetime covers the boundary a cap
// cannot express. A session with nothing left has no honest Max-Age: any
// non-negative number tells the browser to keep presenting a value the OP
// will reject. The caller is handed an error so it clears the cookie
// instead, and the error is a distinguishable sentinel so "the session is
// over" is not confused with "the profile is malformed".
func TestBuildSession_RefusesElapsedLifetime(t *testing.T) {
	t.Parallel()

	now := buildSessionNow()
	for _, expiresAt := range []time.Time{now, now.Add(-time.Nanosecond), now.Add(-time.Hour)} {
		c, err := cookie.BuildSession("sealed-payload", expiresAt, now)
		if !errors.Is(err, cookie.ErrSessionExpired) {
			t.Errorf("expiresAt=%v: err=%v want ErrSessionExpired", expiresAt, err)
		}
		if c != nil {
			t.Errorf("expiresAt=%v: cookie returned with Max-Age=%d despite the elapsed lifetime",
				expiresAt, c.MaxAge)
		}
	}
}
