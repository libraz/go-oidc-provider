package authorizeendpoint

import (
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
)

func TestSetSessionCookie_SubsecondRemainingUsesOneSecond(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	w := httptest.NewRecorder()
	if err := setSessionCookie(w, "sealed", now.Add(500*time.Millisecond), now); err != nil {
		t.Fatalf("setSessionCookie: %v", err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != cookie.SessionProfile.Name {
		t.Fatalf("Set-Cookie=%v want one %q cookie", cookies, cookie.SessionProfile.Name)
	}
	if cookies[0].MaxAge != 1 {
		t.Fatalf("MaxAge=%d want 1 for positive sub-second remaining lifetime", cookies[0].MaxAge)
	}
}

// The authorize path and /end_session must agree on Max-Age for the same
// expiry, and an elapsed expiry must surface as the session manager's own
// expired-session error with no cookie written.
func TestSetSessionCookie_MatchesSharedBuilder(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	for _, expiresAt := range []time.Time{{}, now.Add(90 * time.Minute), now.Add(400 * 24 * time.Hour)} {
		w := httptest.NewRecorder()
		if err := setSessionCookie(w, "sealed", expiresAt, now); err != nil {
			t.Fatalf("expiresAt=%v: setSessionCookie: %v", expiresAt, err)
		}
		want, err := cookie.BuildSession("sealed", expiresAt, now)
		if err != nil {
			t.Fatalf("expiresAt=%v: BuildSession: %v", expiresAt, err)
		}
		got := w.Result().Cookies()
		if len(got) != 1 || got[0].MaxAge != want.MaxAge {
			t.Errorf("expiresAt=%v: Set-Cookie=%v want MaxAge=%d", expiresAt, got, want.MaxAge)
		}
	}

	w := httptest.NewRecorder()
	if err := setSessionCookie(w, "sealed", now, now); !errors.Is(err, sessions.ErrCurrentSessionExpired) {
		t.Fatalf("elapsed expiry err=%v want ErrCurrentSessionExpired", err)
	}
	if got := w.Result().Cookies(); len(got) != 0 {
		t.Fatalf("elapsed expiry wrote Set-Cookie=%v", got)
	}
}
