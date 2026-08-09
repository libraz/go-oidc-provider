// White-box tests for what /authorize emits when a JARM response
// cannot be produced. The contract under test: a failure to sign never
// downgrades the response to a weaker shape than the one the client
// contracted for. Concretely, under response_mode=form_post.jwt the
// authorization code MUST NOT be delivered through a redirect — a 302
// puts it in browser history, in the Referer of whatever the landing
// page loads, and in every proxy log on the path, which is the exact
// exposure a form-post mode exists to avoid.
//
//nolint:testpackage // intentional white-box test for unexported emit helpers.
package authorizeendpoint

import (
	"net/http"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorize"
)

// unsignableRequest returns a JARM request in the supplied mode whose
// payload the signer refuses: JARM mandates an "aud" claim and
// [jarm.Signer.SignDefault] takes it from client_id. Clearing the field
// is a deterministic stand-in for any signing failure the endpoint can
// meet at runtime (key unavailable, JOSE encoder error) — every one of
// them reaches the same branch with the same non-encryption error.
func unsignableRequest(f *jarmTestFixture, mode string) *authorize.Request {
	req := f.authorizeRequest(mode)
	req.ClientID = ""
	return req
}

// TestEmitAuthorizeSuccess_FormPostJWTSigningFailure_NeverRedirectsCode
// is the core regression pin: a signing failure under form_post.jwt
// must not answer with a 302, and the authorization code must not
// appear anywhere in the response.
func TestEmitAuthorizeSuccess_FormPostJWTSigningFailure_NeverRedirectsCode(t *testing.T) {
	t.Parallel()

	f := newJARMTestFixture(t, false, false)
	const code = "the-authorization-code"
	w := dispatchSuccess(f, unsignableRequest(f, "form_post.jwt"), code)

	if w.Code == http.StatusFound {
		t.Fatalf("status=302 (Location=%q); a form-post request must never be answered with a redirect",
			w.Header().Get("Location"))
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Fatalf("Location=%q; no redirect may be emitted for a form-post request", loc)
	}
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 (auto-submitted form)", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, code) {
		t.Fatalf("authorization code leaked into the response body: %s", body)
	}
	if !strings.Contains(body, `name="error" value="server_error"`) {
		t.Fatalf("response is not the determinate server_error envelope: %s", body)
	}
	if !strings.Contains(body, "jarm_response_signing_failed") {
		t.Fatalf("response does not name the failure: %s", body)
	}
}

// TestEmitAuthorizeSuccess_QueryJWTSigningFailure_WithholdsCode covers
// the redirect-mode half. A redirect is the transport the client chose
// here, so emitting one is correct — but the payload must be the error,
// never the unsigned code, because a plain "?code=..." drops the JARM
// binding the client asked for.
func TestEmitAuthorizeSuccess_QueryJWTSigningFailure_WithholdsCode(t *testing.T) {
	t.Parallel()

	f := newJARMTestFixture(t, false, false)
	const code = "the-authorization-code"
	w := dispatchSuccess(f, unsignableRequest(f, "query.jwt"), code)

	if w.Code != http.StatusFound {
		t.Fatalf("status=%d want 302 for a redirect-mode request", w.Code)
	}
	loc := w.Header().Get("Location")
	if strings.Contains(loc, code) {
		t.Fatalf("authorization code leaked into the redirect: %s", loc)
	}
	if !strings.Contains(loc, "error=server_error") {
		t.Fatalf("redirect is not the determinate server_error envelope: %s", loc)
	}
	if !strings.Contains(loc, "jarm_response_signing_failed") {
		t.Fatalf("redirect does not name the failure: %s", loc)
	}
}

// TestEmitAuthorizeError_FormPostJWTSigningFailure_StaysOnFormPost pins
// the error-path twin. No credential is at stake here, so the original
// wire code survives — but the transport the client selected does too,
// because the string compare that used to pick the transport matched
// only the literal "form_post" and silently missed "form_post.jwt".
func TestEmitAuthorizeError_FormPostJWTSigningFailure_StaysOnFormPost(t *testing.T) {
	t.Parallel()

	f := newJARMTestFixture(t, false, false)
	w := dispatchError(f, unsignableRequest(f, "form_post.jwt"), errAccessDenied, "user aborted the interaction")

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 (auto-submitted form); Location=%q",
			w.Code, w.Header().Get("Location"))
	}
	body := w.Body.String()
	if !strings.Contains(body, `name="error" value="access_denied"`) {
		t.Fatalf("original wire code not preserved: %s", body)
	}
}

// TestResponseModeUsesFormPost enumerates the modes whose responses are
// delivered as an auto-submitted form. The predicate is what every
// fallback consults instead of comparing against the "form_post"
// literal; a row flipping to false is a redirect the client did not ask
// for.
func TestResponseModeUsesFormPost(t *testing.T) {
	t.Parallel()

	cases := []struct {
		mode string
		want bool
	}{
		{"form_post", true},
		{"form_post.jwt", true},
		{"", false},
		{"query", false},
		{"query.jwt", false},
		{"fragment.jwt", false},
		// The bare JARM alias resolves against response_type=code,
		// which JARM §4.3 maps onto query.jwt.
		{"jwt", false},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			t.Parallel()
			req := &authorize.Request{ResponseType: "code", ResponseMode: tc.mode}
			if got := responseModeUsesFormPost(req); got != tc.want {
				t.Errorf("responseModeUsesFormPost(%q) = %v want %v", tc.mode, got, tc.want)
			}
		})
	}
}
