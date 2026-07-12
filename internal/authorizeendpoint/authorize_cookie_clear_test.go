package authorizeendpoint_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestAuthorize_TamperedSessionCookieIsCleared pins L-13: a tampered /
// undecodable __Host-oidc_session cookie is treated as "no session" AND
// expired at the browser, rather than left in place. Without the fix the
// corrupted cookie is re-sent on every subsequent request and re-fails the
// decode; the handler now emits a clearing Set-Cookie so the browser
// starts clean.
func TestAuthorize_TamperedSessionCookieIsCleared(t *testing.T) {
	t.Parallel()

	clock := fakeClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t, testkit.WithClock(clock))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-clear",
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "none",
		PublicClient:            true,
	})

	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	authorizeURL := tk.Server.URL + "/oidc/auth?" + e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0]).Encode()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authorizeURL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// A tampered cookie value the session manager cannot decode → ErrCookieInvalid.
	req.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: "not-a-valid-session-token"})

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()

	cleared := findCookie(resp.Cookies(), cookie.SessionProfile.Name)
	if cleared == nil {
		t.Fatalf("no Set-Cookie for %s; tampered cookie was not cleared", cookie.SessionProfile.Name)
	}
	if cleared.MaxAge >= 0 && cleared.Value != "" {
		t.Fatalf("session cookie not expired: MaxAge=%d value=%q", cleared.MaxAge, cleared.Value)
	}
}
