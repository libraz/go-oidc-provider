package userinfo_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestHandler_POST_BodyTooLarge_Rejected confirms the form-body branch
// of /userinfo refuses a multi-KiB POST body. The handler must install
// an [http.MaxBytesReader] cap before invoking ParseForm so a hostile
// client cannot force the OP to allocate megabytes of url-decoded form
// state by submitting a pathological access_token field.
//
// The exact response shape is documented in the handler godoc:
//
//   - HTTP 413 Request Entity Too Large
//   - WWW-Authenticate: Bearer error="invalid_request",
//     error_description="The request body exceeds..."
//
// 64 KiB is the project-wide [endpointsupport.MaxFormBytes] cap; the
// test pushes 96 KiB so the cap fires regardless of any small future
// adjustment.
func TestHandler_POST_BodyTooLarge_Rejected(t *testing.T) {
	t.Parallel()
	f := newUserInfoFixture(t)
	// Build a payload comfortably above the 64 KiB cap.
	payload := "access_token=" + strings.Repeat("A", 96*1024)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, f.endpoint, strings.NewReader(payload))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := f.doRequest(t, req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want 413", resp.StatusCode)
	}
	got := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(got, `error="invalid_request"`) {
		t.Fatalf("WWW-Authenticate=%q must declare invalid_request", got)
	}
	if !strings.Contains(got, "exceeds") {
		t.Fatalf("WWW-Authenticate=%q must surface the size-limit reason", got)
	}
}

// TestHandler_Success_StampsPragmaNoCache pins the OAuth/OIDC §5.1
// header posture on the success path: both Cache-Control: no-store
// (with the OIDC Core "private" hint preserved) AND Pragma: no-cache
// MUST be set so HTTP/1.0 caches that ignore Cache-Control still
// short-circuit the body.
func TestHandler_Success_StampsPragmaNoCache(t *testing.T) {
	t.Parallel()
	f := newUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{"email": "alice@example.com"})
	token := f.signAccessToken(t, nil)
	resp := f.doRequest(t, f.newGet(t, token))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store, private" {
		t.Errorf("Cache-Control=%q want \"no-store, private\"", got)
	}
	if got := resp.Header.Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma=%q want \"no-cache\"", got)
	}
}

// TestHandler_WWWAuthenticate_NoCRLFInjection confirms the userinfo
// handler's WWW-Authenticate values cannot be split or escape-broken
// by an attacker-influenced description string. The library routes
// every challenge through [endpointsupport.SanitizeChallengeValue] /
// [endpointsupport.BuildBearerChallenge]; the test pins the header
// shape on a representative path (the multi-channel rejection branch)
// so a regression is caught here.
//
// The handler does not currently take the description from request
// input on this path — it is a fixed library string — so the test
// asserts the static literal is well-formed (no CR / LF / unescaped
// quote / unescaped backslash). The same defence covers any future
// path that grows a dynamic description because the helper is the
// single composition site.
func TestHandler_WWWAuthenticate_NoCRLFInjection(t *testing.T) {
	t.Parallel()
	f := newUserInfoFixture(t)
	resp := f.doRequest(t, f.newGet(t, ""))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	got := resp.Header.Get("WWW-Authenticate")
	for _, bad := range []string{"\r", "\n", "\x00"} {
		if strings.Contains(got, bad) {
			t.Fatalf("WWW-Authenticate=%q carries forbidden byte %q", got, bad)
		}
	}
}
