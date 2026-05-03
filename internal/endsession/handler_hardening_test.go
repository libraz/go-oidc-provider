package endsession_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestHandler_GET_QueryStringTooLong_Rejected confirms the GET branch
// caps the request URI's RawQuery at the documented 8 KiB. A hostile
// RP that crafts a multi-megabyte query string would otherwise force
// the OP to allocate megabytes of url-decoded form state before the
// per-field validation runs; the cap fires before parseRequest is
// invoked so the response stays cheap.
func TestHandler_GET_QueryStringTooLong_Rejected(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	// The cap is 8 KiB; build a query string at 16 KiB so the test
	// fires regardless of any small future adjustment.
	huge := strings.Repeat("A", 16*1024)
	target := h.endSessionPath + "?state=" + huge
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestURITooLong {
		t.Fatalf("status=%d want 414 (request URI too long)", resp.StatusCode)
	}
}

// TestHandler_GET_StateTooLong_Rejected confirms the per-field cap on
// state. 4 KiB is over the documented 2 KiB ceiling but well below
// the 8 KiB query cap, so the per-field rule is what fires here.
func TestHandler_GET_StateTooLong_Rejected(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	huge := strings.Repeat("S", 4*1024)
	v := url.Values{"state": {huge}}
	resp := h.doGET(t, v, "")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestURITooLong {
		t.Fatalf("status=%d want 414", resp.StatusCode)
	}
}

// TestHandler_GET_StateAtBoundary_Accepted confirms a state at exactly
// the 2 KiB cap is admitted (no off-by-one regression). The request
// has no id_token_hint so the GET still renders the interstitial; the
// test only asserts the gate did not fire.
func TestHandler_GET_StateAtBoundary_Accepted(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	v := url.Values{"state": {strings.Repeat("S", 2*1024)}}
	resp := h.doGET(t, v, "")
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusRequestURITooLong {
		t.Fatalf("status=414 unexpected at exact cap")
	}
}

// TestHandler_IDTokenHint_Stale_Rejected confirms the OP rejects an
// id_token_hint whose iat is older than 30 days. The signature still
// verifies (the test signs with the OP's active key), but the age
// gate refuses to admit ancient tokens to the logout flow so an
// attacker who exfiltrates a long-forgotten id_token cannot replay it
// indefinitely.
func TestHandler_IDTokenHint_Stale_Rejected(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookieValue, _ := h.issueSession(t)
	// 31 days back: just past the 30-day cap.
	ancient := h.signIDToken(t, func(claims map[string]any) {
		claims["iat"] = h.clock.now.Add(-31 * 24 * time.Hour).Unix()
	})
	v := url.Values{}
	v.Set("id_token_hint", ancient)
	v.Set("post_logout_redirect_uri", h.postLogoutURI)
	resp := h.doGET(t, v, cookieValue)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400; stale id_token_hint must be rejected", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "invalid id_token_hint") {
		t.Errorf("body=%q must surface the conflated id_token_hint failure", body)
	}
}

// TestHandler_IDTokenHint_FreshAdmitted confirms the freshness gate
// does not regress the happy path: an id_token_hint whose iat is
// inside the 30-day window continues to flow through to the redirect.
func TestHandler_IDTokenHint_FreshAdmitted(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookieValue, _ := h.issueSession(t)
	// 7 days back: well inside the cap.
	fresh := h.signIDToken(t, func(claims map[string]any) {
		claims["iat"] = h.clock.now.Add(-7 * 24 * time.Hour).Unix()
	})
	v := url.Values{}
	v.Set("id_token_hint", fresh)
	v.Set("post_logout_redirect_uri", h.postLogoutURI)
	resp := h.doGET(t, v, cookieValue)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302; fresh id_token_hint should redirect", resp.StatusCode)
	}
}

// TestHandler_IDTokenHint_NoIatAdmitted confirms the freshness gate is
// gated on the presence of "iat": tokens that omit the claim continue
// to flow under the legacy posture (signature / issuer / aud are
// sufficient to identify the requesting client). This preserves
// backward compatibility with embedders whose id_tokens predate the
// freshness check.
func TestHandler_IDTokenHint_NoIatAdmitted(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	cookieValue, _ := h.issueSession(t)
	// No iat at all.
	noIat := h.signIDToken(t, func(claims map[string]any) {
		delete(claims, "iat")
	})
	v := url.Values{}
	v.Set("id_token_hint", noIat)
	v.Set("post_logout_redirect_uri", h.postLogoutURI)
	resp := h.doGET(t, v, cookieValue)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302 (no iat -> legacy posture)", resp.StatusCode)
	}
}
