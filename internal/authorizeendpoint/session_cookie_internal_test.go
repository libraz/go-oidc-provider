package authorizeendpoint

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/cookie"
)

func TestSetSessionCookieWithMaxAge_SubsecondRemainingUsesOneSecond(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)
	w := httptest.NewRecorder()
	if err := setSessionCookieWithMaxAge(w, "sealed", now.Add(500*time.Millisecond), now); err != nil {
		t.Fatalf("setSessionCookieWithMaxAge: %v", err)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != cookie.SessionProfile.Name {
		t.Fatalf("Set-Cookie=%v want one %q cookie", cookies, cookie.SessionProfile.Name)
	}
	if cookies[0].MaxAge != 1 {
		t.Fatalf("MaxAge=%d want 1 for positive sub-second remaining lifetime", cookies[0].MaxAge)
	}
}
