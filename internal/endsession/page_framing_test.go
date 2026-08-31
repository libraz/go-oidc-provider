package endsession_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestHandler_HTMLPagesRefuseFraming pins the framing defense on every
// HTML document /end_session renders. Both pages carry a one-click state
// change: the interstitial's submit button destroys the session and
// cascades a revocation across grants and tokens, and the confirmation
// page is the outcome a framer wants the user to believe they reached.
//
// A same-site framer (a hijacked subdomain, a sibling host) can UI-redress
// that button into a forced sign-out: the session cookie is SameSite=Lax
// and the CSRF token lives inside the frame, so every other gate passes.
// The CSP sandbox directive constrains what the document itself may do and
// says nothing about who may frame it, so both frame-ancestors 'none' and
// X-Frame-Options: DENY have to be present, on every response branch.
func TestHandler_HTMLPagesRefuseFraming(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		// respond drives one HTML-producing branch of the endpoint.
		respond func(t *testing.T, h *harness) *http.Response
		// marker identifies the page in the body, so a branch that
		// silently starts rendering a different document is caught.
		marker string
	}{
		{
			name: "interstitial",
			respond: func(t *testing.T, h *harness) *http.Response {
				t.Helper()
				cookieValue, _ := h.issueSession(t)
				return h.doGET(t, url.Values{}, cookieValue)
			},
			marker: "Confirm sign-out",
		},
		{
			name: "signed out confirmation",
			respond: func(t *testing.T, h *harness) *http.Response {
				t.Helper()
				cookieValue, _ := h.issueSession(t)
				return confirmScope(t, h, url.Values{}, cookieValue)
			},
			// The apostrophe is html-escaped at the substitution site.
			marker: "You&#39;re signed out",
		},
		{
			name: "error page",
			respond: func(t *testing.T, h *harness) *http.Response {
				t.Helper()
				return h.doGET(t, url.Values{"id_token_hint": {"not-a-jws"}}, "")
			},
			marker: "Sign-out failed",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t)
			resp := tc.respond(t, h)
			body := readBody(t, resp)
			if !strings.Contains(body, tc.marker) {
				t.Fatalf("branch did not render the expected page (marker %q): %s", tc.marker, body)
			}
			if got := resp.Header.Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("X-Frame-Options=%q want DENY", got)
			}
			if got := resp.Header.Get("Content-Security-Policy"); !strings.Contains(got, "frame-ancestors 'none'") {
				t.Errorf("Content-Security-Policy=%q missing frame-ancestors 'none'", got)
			}
		})
	}
}
