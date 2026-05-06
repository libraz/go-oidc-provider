//nolint:testpackage // exercises unexported helpers (fetchJARRequestURI, isJARRequestObjectContentType) for SSRF / content-type coverage.
package authorizeendpoint

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// fakeClient returns a [*store.Client] with the supplied URI in its
// RequestURIs allowlist so [fetchJARRequestURI] passes the
// preregistration check and proceeds to the network leg under test.
func fakeClient(uri string) *store.Client {
	return &store.Client{
		ID:           "fake-client",
		RequestURIs:  []string{uri},
		RedirectURIs: []string{"https://rp.example/cb"},
	}
}

// decodeWireError parses the OAuth JSON envelope written by
// [renderJSONError] and returns the error / description fields. Tests
// branch on the description so a regression that changes the wire
// shape surfaces immediately rather than silently passing the SSRF
// gate while emitting a misleading wire string.
func decodeWireError(t *testing.T, rec *httptest.ResponseRecorder) (string, string) {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode envelope: %v (raw=%q)", err, rec.Body.String())
	}
	code, _ := body["error"].(string)
	desc, _ := body["error_description"].(string)
	return code, desc
}

// TestFetchJARRequestURI_HTTPSOnlyByDefault pins the production
// posture: an http:// request_uri is refused without
// AllowPrivateNetworkJAR even when the URI is preregistered.
func TestFetchJARRequestURI_HTTPSOnlyByDefault(t *testing.T) {
	t.Parallel()

	uri := "http://example.com/req"
	rec := httptest.NewRecorder()
	body, ok := fetchJARRequestURI(context.Background(), rec, fakeClient(uri), uri, false /*allowPrivate*/)
	if ok {
		t.Fatalf("fetchJARRequestURI succeeded; want refusal. body=%q", body)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rec.Code)
	}
	code, desc := decodeWireError(t, rec)
	if code != "invalid_request_uri" {
		t.Fatalf("error=%q want invalid_request_uri", code)
	}
	if !strings.Contains(desc, "scheme") {
		t.Fatalf("description=%q must mention scheme", desc)
	}
}

// TestFetchJARRequestURI_AllowPrivateAdmitsHTTP confirms the test /
// dev escape hatch: an http:// loopback URI is admitted only when
// the caller opts into AllowPrivateNetworkJAR.
func TestFetchJARRequestURI_AllowPrivateAdmitsHTTP(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")
		_, _ = w.Write([]byte("eyJhbGciOiJSUzI1NiJ9.PAYLOAD.SIGNATURE"))
	}))
	defer srv.Close()

	uri := srv.URL + "/req"
	rec := httptest.NewRecorder()
	body, ok := fetchJARRequestURI(context.Background(), rec, fakeClient(uri), uri, true /*allowPrivate*/)
	if !ok {
		t.Fatalf("fetchJARRequestURI failed: status=%d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.HasPrefix(body, "eyJ") {
		t.Fatalf("body=%q does not look like a JWS", body)
	}
}

// TestFetchJARRequestURI_BlocksCloudMetadataEvenWithAllowPrivate is
// the primary security regression: AllowPrivateNetworkJAR widens the
// SSRF gate to admit loopback / RFC 1918, but cloud-metadata IPs
// remain rejected so an attacker-controlled request_uri cannot pivot
// the OP onto IMDS / the GCP metadata server even when the deployment
// has opted into private networks.
func TestFetchJARRequestURI_BlocksCloudMetadataEvenWithAllowPrivate(t *testing.T) {
	t.Parallel()

	uri := "http://169.254.169.254/latest/meta-data/"
	rec := httptest.NewRecorder()
	body, ok := fetchJARRequestURI(context.Background(), rec, fakeClient(uri), uri, true /*allowPrivate*/)
	if ok {
		t.Fatalf("fetchJARRequestURI accepted cloud metadata under AllowPrivate; body=%q", body)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rec.Code)
	}
	code, desc := decodeWireError(t, rec)
	if code != "invalid_request_uri" {
		t.Fatalf("error=%q want invalid_request_uri", code)
	}
	if !strings.Contains(desc, "metadata") {
		t.Fatalf("description=%q must mention cloud metadata", desc)
	}
}

// TestFetchJARRequestURI_RefusesRedirect pins the redirect-refusal
// posture: a 30x response from an allowlisted upstream must NOT be
// followed because the location target is outside the SSRF gate the
// preregistered URI passed.
func TestFetchJARRequestURI_RefusesRedirect(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, "https://attacker.example/elsewhere", http.StatusFound)
	}))
	defer srv.Close()

	uri := srv.URL + "/req"
	rec := httptest.NewRecorder()
	body, ok := fetchJARRequestURI(context.Background(), rec, fakeClient(uri), uri, true /*allowPrivate*/)
	if ok {
		t.Fatalf("fetchJARRequestURI followed a redirect; body=%q", body)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rec.Code)
	}
	code, desc := decodeWireError(t, rec)
	if code != "invalid_request_uri" {
		t.Fatalf("error=%q want invalid_request_uri", code)
	}
	if !strings.Contains(desc, "redirect") {
		t.Fatalf("description=%q must mention redirect", desc)
	}
}

// TestFetchJARRequestURI_RefusesNonJWSContentType pins the
// content-type whitelist: an HTML / octet-stream body MUST be
// refused so a captive portal or misrouted CDN response cannot reach
// the JWS verifier.
func TestFetchJARRequestURI_RefusesNonJWSContentType(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<html>not a JWS</html>"))
	}))
	defer srv.Close()

	uri := srv.URL + "/req"
	rec := httptest.NewRecorder()
	body, ok := fetchJARRequestURI(context.Background(), rec, fakeClient(uri), uri, true /*allowPrivate*/)
	if ok {
		t.Fatalf("fetchJARRequestURI accepted text/html; body=%q", body)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rec.Code)
	}
	code, desc := decodeWireError(t, rec)
	if code != "invalid_request_uri" {
		t.Fatalf("error=%q want invalid_request_uri", code)
	}
	if !strings.Contains(desc, "content-type") {
		t.Fatalf("description=%q must mention content-type", desc)
	}
}

// TestFetchJARRequestURI_AcceptsAbsentContentType pins compatibility
// with IdPs that publish bare JWS bodies without a Content-Type
// header. RFC 9101 §10.6 SHOULDs application/oauth-authz-req+jwt; an
// absent value is treated as compatible rather than an error.
func TestFetchJARRequestURI_AcceptsAbsentContentType(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Intentionally do not set Content-Type.
		_, _ = w.Write([]byte("eyJhbGciOiJSUzI1NiJ9.PAYLOAD.SIG"))
	}))
	defer srv.Close()

	uri := srv.URL + "/req"
	rec := httptest.NewRecorder()
	body, ok := fetchJARRequestURI(context.Background(), rec, fakeClient(uri), uri, true /*allowPrivate*/)
	if !ok {
		t.Fatalf("fetchJARRequestURI rejected absent Content-Type: status=%d body=%q",
			rec.Code, rec.Body.String())
	}
	if !strings.HasPrefix(body, "eyJ") {
		t.Fatalf("body=%q does not look like a JWS", body)
	}
}

// TestFetchJARRequestURI_BodyCapEnforced confirms a too-large body
// surfaces as a refusal even when content-type is otherwise valid.
func TestFetchJARRequestURI_BodyCapEnforced(t *testing.T) {
	t.Parallel()

	oversized := strings.Repeat("A", int(maxJARRequestURIBody)+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte(oversized))
	}))
	defer srv.Close()

	uri := srv.URL + "/req"
	rec := httptest.NewRecorder()
	body, ok := fetchJARRequestURI(context.Background(), rec, fakeClient(uri), uri, true /*allowPrivate*/)
	if ok {
		t.Fatalf("fetchJARRequestURI accepted oversized body; len=%d", len(body))
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rec.Code)
	}
	code, desc := decodeWireError(t, rec)
	if code != "invalid_request_uri" {
		t.Fatalf("error=%q want invalid_request_uri", code)
	}
	if !strings.Contains(desc, "size cap") {
		t.Fatalf("description=%q must mention size cap", desc)
	}
}

// TestFetchJARRequestURI_RejectsUnregisteredURI confirms the
// preregistration gate fires before the SSRF gate so an unallowed URI
// does not even reach the network leg.
func TestFetchJARRequestURI_RejectsUnregisteredURI(t *testing.T) {
	t.Parallel()

	registered := "https://allowed.example/req"
	probe := "https://attacker.example/req"
	rec := httptest.NewRecorder()
	body, ok := fetchJARRequestURI(context.Background(), rec, fakeClient(registered), probe, false)
	if ok {
		t.Fatalf("fetchJARRequestURI fetched an unregistered URI; body=%q", body)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rec.Code)
	}
	code, desc := decodeWireError(t, rec)
	if code != "invalid_request_uri" {
		t.Fatalf("error=%q want invalid_request_uri", code)
	}
	if !strings.Contains(desc, "preregistered") {
		t.Fatalf("description=%q must mention preregistration", desc)
	}
}

// TestIsJARRequestObjectContentType_Matrix pins the whitelist used by
// the fetcher. The test doubles as a regression guard: a future
// revision that loosens the table will surface here.
func TestIsJARRequestObjectContentType_Matrix(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		ct   string
		want bool
	}{
		{"empty", "", true},
		{"oauth-authz-req+jwt", "application/oauth-authz-req+jwt", true},
		{"oauth-authz-req+jwt-charset", "application/oauth-authz-req+jwt; charset=utf-8", true},
		{"jwt", "application/jwt", true},
		{"text-plain", "text/plain", true},
		{"text-plain-charset", "text/plain; charset=utf-8", true},
		{"text-html", "text/html", false},
		{"json", "application/json", false},
		{"octet-stream", "application/octet-stream", false},
		{"upper-case-jwt", "APPLICATION/JWT", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isJARRequestObjectContentType(tc.ct); got != tc.want {
				t.Fatalf("isJARRequestObjectContentType(%q)=%v want %v", tc.ct, got, tc.want)
			}
		})
	}
}
