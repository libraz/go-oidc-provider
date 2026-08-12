// White-box tests for what /authorize emits when a JARM response
// cannot be produced. The contract under test is fail-closed: every
// signing, key, encryption, or form-rendering failure produces an
// endpoint-local 500 with no redirect, partial form, state, code, or
// OAuth error fields.
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

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 (OP-local failure)", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Fatalf("Location=%q; no redirect may be emitted for a JARM failure", loc)
	}
	body := w.Body.String()
	for _, secret := range []string{code, "server_error", "jarm_response_signing_failed", "state-abc"} {
		if strings.Contains(body, secret) {
			t.Fatalf("JARM failure exposed %q in response body: %s", secret, body)
		}
	}
}

// TestEmitAuthorizeSuccess_QueryJWTSigningFailure_WithholdsCode covers
// the redirect-mode half. JARM failure handling is transport-independent:
// even though the request selected a redirect-capable JARM mode, the
// OP must not emit a redirect or reflect the unsigned code/error.
func TestEmitAuthorizeSuccess_QueryJWTSigningFailure_WithholdsCode(t *testing.T) {
	t.Parallel()

	f := newJARMTestFixture(t, false, false)
	const code = "the-authorization-code"
	w := dispatchSuccess(f, unsignableRequest(f, "query.jwt"), code)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 for a redirect-mode JARM failure", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Fatalf("Location=%q; no redirect may be emitted for a JARM failure", loc)
	}
	for _, secret := range []string{code, "server_error", "jarm_response_signing_failed", "state-abc"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("JARM failure exposed %q in response body: %s", secret, w.Body.String())
		}
	}
}

// TestEmitAuthorizeError_JARMSigningFailure_FailsClosedLocally pins the
// error-path twin. The original OAuth error, state, and transport are
// all withheld when its JARM envelope cannot be produced.
func TestEmitAuthorizeError_JARMSigningFailure_FailsClosedLocally(t *testing.T) {
	t.Parallel()

	f := newJARMTestFixture(t, false, false)
	w := dispatchError(f, unsignableRequest(f, "form_post.jwt"), errAccessDenied, "user aborted the interaction")

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 (OP-local failure); Location=%q",
			w.Code, w.Header().Get("Location"))
	}
	if loc := w.Header().Get("Location"); loc != "" {
		t.Fatalf("Location=%q; no redirect may be emitted for a JARM failure", loc)
	}
	for _, secret := range []string{"access_denied", "user aborted the interaction", "state-abc"} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatalf("JARM failure exposed %q in response body: %s", secret, w.Body.String())
		}
	}
}

// TestResponseModeUsesFormPost enumerates the modes whose responses are
// delivered as an auto-submitted form. The predicate is what every
// plain form-post selection consults instead of comparing against the
// "form_post" literal; a row flipping to false is a redirect the client
// did not ask for.
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
