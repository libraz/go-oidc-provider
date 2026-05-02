// Package httptest centralises the HTTP request / response helpers that
// every endpoint test fixture (token / introspect / revoke / par /
// userinfo) used to copy verbatim. Each fixture wired its own
// post(form, basicID, basicSecret) variant that produced an
// application/x-www-form-urlencoded request, optionally stamped Basic
// auth, and dispatched it through the testkit Provider's pinned HTTP
// client. The duplication added up to roughly one hundred lines spread
// across four files; the helpers below replace those copies with a
// single, named contract so the call sites read as
// httptest.PostForm(...) and the wire shape (Content-Type, Accept,
// Authorization) is documented in one place.
//
// The helpers accept the caller's [*http.Client] rather than the
// testkit Provider so the package stays decoupled from op/testkit.
// Fixtures pass prov.HTTPClient(nil); other callers can pass any
// configured client (for example a TLS-pinned one).
package httptest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// PostForm issues a POST application/x-www-form-urlencoded request
// against endpoint with the supplied form values. When basicID is
// non-empty the helper additionally stamps Basic authentication using
// (basicID, basicSecret); leaving basicID empty elides the header so
// the handler observes the unauthenticated case.
//
// The helper fails the test on transport errors. Callers own
// [http.Response.Body.Close] because the response body often carries
// the assertion payload.
func PostForm(tb testing.TB, client *http.Client, endpoint string, form url.Values, basicID, basicSecret string) *http.Response {
	tb.Helper()
	return PostFormWithAccept(tb, client, endpoint, form, basicID, basicSecret, "")
}

// PostFormWithAccept extends [PostForm] with an explicit Accept header.
// RFC 9701 §5 negotiates the introspection response format on Accept,
// so the JWT-path tests need a knob the JSON-path helper does not
// expose. An empty accept argument leaves the header unset, matching
// [PostForm] exactly.
func PostFormWithAccept(tb testing.TB, client *http.Client, endpoint string, form url.Values, basicID, basicSecret, accept string) *http.Response {
	tb.Helper()
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if basicID != "" {
		req.SetBasicAuth(basicID, basicSecret)
	}
	resp, err := client.Do(req)
	if err != nil {
		tb.Fatalf("Do: %v", err)
	}
	return resp
}

// GetWithBearer issues a GET request against endpoint with the given
// bearer access token. An empty token elides the Authorization header
// so the handler observes the "no credentials" case (the userinfo
// suite uses this to drive the WWW-Authenticate path).
func GetWithBearer(tb testing.TB, client *http.Client, endpoint, token string) *http.Response {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, endpoint, http.NoBody)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		tb.Fatalf("Do: %v", err)
	}
	return resp
}

// DecodeJSON parses resp.Body as a JSON object. The response body is
// fully drained so callers may close it without losing diagnostics.
// Empty bodies produce an empty map rather than an error so 204 / no
// content endpoints (revoke) can share the same helper.
func DecodeJSON(tb testing.TB, resp *http.Response) map[string]any {
	tb.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("ReadAll: %v", err)
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		tb.Fatalf("Unmarshal(%s): %v", raw, err)
	}
	return out
}
