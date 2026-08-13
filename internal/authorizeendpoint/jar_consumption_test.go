//nolint:testpackage // exercises unexported helpers (fetchJARRequestURI, isJARRequestObjectContentType) for SSRF / content-type coverage.
package authorizeendpoint

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/libraz/go-oidc-provider/op/interaction"
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

// jarFetchRequest returns the inbound request a JAR-stage rejection is
// rendered against. No Accept header is set, so the content negotiation
// in [renderBrowserError] stays on the JSON envelope most of these tests
// decode; a caller that wants the browser branch sets Accept itself.
func jarFetchRequest() *http.Request {
	return httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize", nil)
}

// jarFetchDeps returns the minimal [resolved] the fetcher reads: the
// private-network toggle, and a nil Driver so rejections render as JSON.
// It goes through [resolveDeps] so the shared outbound client is built
// the same way production builds it.
func jarFetchDeps(allowPrivate bool) resolved {
	return resolveDeps(Deps{AllowPrivateNetworkJAR: allowPrivate})
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
	body, ok := fetchJARRequestURI(rec, jarFetchRequest(), jarFetchDeps(false), fakeClient(uri), uri, "")
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
	body, ok := fetchJARRequestURI(rec, jarFetchRequest(), jarFetchDeps(true), fakeClient(uri), uri, "")
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
	body, ok := fetchJARRequestURI(rec, jarFetchRequest(), jarFetchDeps(true), fakeClient(uri), uri, "")
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
	body, ok := fetchJARRequestURI(rec, jarFetchRequest(), jarFetchDeps(true), fakeClient(uri), uri, "")
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
	body, ok := fetchJARRequestURI(rec, jarFetchRequest(), jarFetchDeps(true), fakeClient(uri), uri, "")
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
	body, ok := fetchJARRequestURI(rec, jarFetchRequest(), jarFetchDeps(true), fakeClient(uri), uri, "")
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
	body, ok := fetchJARRequestURI(rec, jarFetchRequest(), jarFetchDeps(true), fakeClient(uri), uri, "")
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
	body, ok := fetchJARRequestURI(rec, jarFetchRequest(), jarFetchDeps(false), fakeClient(registered), probe, "")
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

// TestResolveJARRequestIfNeeded_RendersThroughTheDriver pins that a
// JAR-stage rejection reaches the embedder's interaction driver like
// every other pre-redirect /authorize failure. Under a profile that
// mandates signed requests every /authorize call carries a request
// object, so this is the error page the deployment's users actually
// meet; emitting a raw JSON body there is a visible regression from
// what the same failure produces one gate later.
//
// The nil-JAR branch stands in for the whole family: every rejection in
// the function goes through the same renderer.
func TestResolveJARRequestIfNeeded_RendersThroughTheDriver(t *testing.T) {
	t.Parallel()

	values := url.Values{
		"request":   {"not.a.jws"},
		"client_id": {"rp-jar"},
		"state":     {"state-abc"},
	}
	deps := resolveDeps(Deps{Driver: interaction.HTMLDriver{}})

	t.Run("browser_gets_the_driver_page", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		req := jarFetchRequest()
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		_, handled, stop := resolveJARRequestIfNeeded(rec, req, deps, "rp-jar", values)
		if !handled || !stop {
			t.Fatalf("handled=%v stop=%v; want the request refused", handled, stop)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Fatalf("Content-Type=%q want text/html; the driver owns the browser surface", ct)
		}
	})

	t.Run("api_caller_keeps_the_json_envelope", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		req := jarFetchRequest()
		_, handled, stop := resolveJARRequestIfNeeded(rec, req, deps, "rp-jar", values)
		if !handled || !stop {
			t.Fatalf("handled=%v stop=%v; want the request refused", handled, stop)
		}
		code, _ := decodeWireError(t, rec)
		if code != "invalid_request" {
			t.Fatalf("error=%q want invalid_request", code)
		}
	})
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

// TestFetchJARRequestURI_ReusesOneConnectionAcrossFetches pins that the
// outbound client is built once per handler rather than once per fetch.
//
// A client rebuilt per request brings its own connection pool, so every
// /authorize carrying a request_uri pays a fresh TCP — in production, TLS
// — handshake against the RP, and leaves behind a pool no later request
// can draw on but which holds its connection open for the idle timeout.
// An unauthenticated caller drives that endpoint.
//
// Counting server-side connections is what distinguishes the two shapes:
// both fetch the same bytes, and only the transport differs.
func TestFetchJARRequestURI_ReusesOneConnectionAcrossFetches(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	opened := 0
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwt")
		_, _ = w.Write([]byte("eyJhbGciOiJSUzI1NiJ9.PAYLOAD.SIG"))
	}))
	srv.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			mu.Lock()
			opened++
			mu.Unlock()
		}
	}
	srv.Start()
	defer srv.Close()

	uri := srv.URL + "/req"
	// One resolved stands in for one mounted handler; both fetches go
	// through it exactly as two requests to the same Provider would.
	deps := jarFetchDeps(true)
	client := fakeClient(uri)
	for i := range 2 {
		rec := httptest.NewRecorder()
		if _, ok := fetchJARRequestURI(rec, jarFetchRequest(), deps, client, uri, ""); !ok {
			t.Fatalf("fetch %d rejected: status=%d body=%q", i+1, rec.Code, rec.Body.String())
		}
	}

	mu.Lock()
	got := opened
	mu.Unlock()
	if got != 1 {
		t.Errorf("the upstream accepted %d connections for 2 fetches, want 1; the fetcher is "+
			"building a new client (and so a new connection pool) per request instead of "+
			"sharing the handler's", got)
	}
}

// TestFetchJARRequestURI_BodyCapPrecedesTheMediaTypeGate pins the order
// the two response-side gates fire in.
//
// The media-type rule this endpoint needs admits an absent header, which
// the shared envelope's allow-list cannot express, so the check sits at
// the call site — after the envelope has already read the body. That is
// only safe while the body cap fires first: an upstream serving an
// oversized body under a media type the OP would reject anyway must
// still be cut off at the cap rather than read to completion and refused
// afterwards. The distinguishing evidence is which of the two refusals
// the caller gets back.
func TestFetchJARRequestURI_BodyCapPrecedesTheMediaTypeGate(t *testing.T) {
	t.Parallel()

	oversized := strings.Repeat("A", int(maxJARRequestURIBody)+1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(oversized))
	}))
	defer srv.Close()

	uri := srv.URL + "/req"
	rec := httptest.NewRecorder()
	body, ok := fetchJARRequestURI(rec, jarFetchRequest(), jarFetchDeps(true), fakeClient(uri), uri, "")
	if ok {
		t.Fatalf("fetchJARRequestURI accepted an oversized non-JWS body; len=%d", len(body))
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", rec.Code)
	}
	code, desc := decodeWireError(t, rec)
	if code != "invalid_request_uri" {
		t.Fatalf("error=%q want invalid_request_uri", code)
	}
	if !strings.Contains(desc, "size cap") {
		t.Fatalf("description=%q want the size-cap refusal; the media-type gate answered first, "+
			"which means the body was read past the cap before anything rejected it", desc)
	}
}
