package parendpoint_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	httptestutil "github.com/libraz/go-oidc-provider/internal/testutil/httptest"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// fixedClock returns a constant Now() reading. Tests inject it through the
// testkit so the OP and the test share an identical view of "now" even on
// expiry-sensitive paths.
type fixedClock struct{ now time.Time }

func (f fixedClock) Now() time.Time { return f.now }

// Compile-time check that the testkit's [op.Clock] satisfies what the
// parendpoint Deps expect.
var _ op.Clock = fixedClock{}

// fixture bundles a fully-wired testkit Provider with the helpers shared
// across the PAR-endpoint test suite. Mirrors the tokenendpoint suite.
type fixture struct {
	prov     *testkit.Provider
	endpoint string
	clock    fixedClock
}

// newFixture builds a fixture pinned to a deterministic clock. The
// 2026-04-26 anchor matches the existing test suites and the docs'
// "today" baseline.
func newFixture(tb testing.TB) *fixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithFeature(feature.PAR)),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/par",
		clock:    clock,
	}
}

// pkcePair returns a PKCE verifier paired with its SHA-256 base64url
// challenge. The verifier length (64) is well inside the 43..128 RFC 7636
// §4.1 bound.
func pkcePair() (verifier, challenge string) {
	verifier = "test-verifier-test-verifier-test-verifier-test-verifier-1234567"
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

// confidentialClient seeds a confidential client whose secret hash matches
// the supplied plaintext, returning the registered client and the plain
// secret for callers to thread through Basic auth.
func (f *fixture) confidentialClient(tb testing.TB) (*store.Client, string) {
	tb.Helper()
	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		tb.Fatalf("Argon2id.Hash: %v", err)
	}
	client := f.prov.RegisterClient(tb, testkit.ClientFixture{
		ID:                      "client-conf-par",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
	})
	return client, secret
}

// publicClient seeds a public client (PKCE-only).
func (f *fixture) publicClient(tb testing.TB) *store.Client {
	tb.Helper()
	return f.prov.RegisterClient(tb, testkit.ClientFixture{
		ID:           "client-pub-par",
		PublicClient: true,
		RedirectURIs: []string{"https://rp.testkit.invalid/callback"},
		Scopes:       []string{"openid", "profile", "email"},
	})
}

// goodAuthorizeForm returns the canonical happy-path authorization form
// payload, ready to be POSTed at /par.
func goodAuthorizeForm(clientID, redirectURI string) url.Values {
	_, challenge := pkcePair()
	return url.Values{
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile email"},
		"state":                 {"par-state-abc"},
		"nonce":                 {"par-nonce-123"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"client_id":             {clientID},
	}
}

// post issues a POST application/x-www-form-urlencoded request with the
// supplied form values. Delegates to [httptestutil.PostForm] so the
// wire shape is documented in one place.
func (f *fixture) post(tb testing.TB, form url.Values, basicID, basicSecret string) *http.Response {
	tb.Helper()
	return httptestutil.PostForm(tb, f.prov.HTTPClient(nil), f.endpoint, form, basicID, basicSecret)
}

// decodeJSON parses resp.Body as a JSON object via the shared helper.
func decodeJSON(tb testing.TB, resp *http.Response) map[string]any {
	tb.Helper()
	return httptestutil.DecodeJSON(tb, resp)
}

// assertCacheControl fails the test if the response is missing the
// no-store / Pragma headers RFC 6749 §5.1 requires.
func assertCacheControl(tb testing.TB, resp *http.Response) {
	tb.Helper()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		tb.Errorf("Cache-Control=%q want no-store", got)
	}
	if got := resp.Header.Get("Pragma"); got != "no-cache" {
		tb.Errorf("Pragma=%q want no-cache", got)
	}
}

// TestHandler_GETRejected confirms /par refuses GET with 405 + Allow.
func TestHandler_GETRejected(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.endpoint, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := f.prov.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); got != http.MethodPost {
		t.Errorf("Allow=%q want POST", got)
	}
	assertCacheControl(t, resp)
}

// TestHandler_WrongContentType refuses non-form bodies with 400
// invalid_request.
func TestHandler_WrongContentType(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, f.endpoint,
		strings.NewReader(`{"response_type":"code"}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.prov.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if body["error"] != "invalid_request" {
		t.Errorf("error=%v want invalid_request", body["error"])
	}
	assertCacheControl(t, resp)
}

// TestHandler_HappyPath_ClientSecretBasic returns a 201 with a request_uri
// and an expires_in matching the configured TTL.
func TestHandler_HappyPath_ClientSecretBasic(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t)
	form := goodAuthorizeForm(client.ID, client.RedirectURIs[0])
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 201; body=%s", resp.StatusCode, dump)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type=%q", got)
	}
	body := decodeJSON(t, resp)
	uri, _ := body["request_uri"].(string)
	if !strings.HasPrefix(uri, "urn:ietf:params:oauth:request_uri:") {
		t.Errorf("request_uri=%q does not match RFC 9126 §2.2 prefix", uri)
	}
	if expires, _ := body["expires_in"].(float64); expires != 60 {
		t.Errorf("expires_in=%v want 60", body["expires_in"])
	}
	assertCacheControl(t, resp)

	// The persisted record must round-trip the request_uri.
	rec, err := f.prov.Store.PushedAuthRequests().Find(context.Background(), uri)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if rec.ClientID != client.ID {
		t.Errorf("rec.ClientID=%q want %q", rec.ClientID, client.ID)
	}
}

// TestHandler_HappyPath_PublicClient confirms a public client with
// TokenEndpointAuthMethod="none" can push an authorization request without
// presenting a secret.
func TestHandler_HappyPath_PublicClient(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client := f.publicClient(t)
	form := goodAuthorizeForm(client.ID, client.RedirectURIs[0])
	// Public clients carry the client_id in the body and no Basic auth.
	resp := f.post(t, form, "", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 201; body=%s", resp.StatusCode, dump)
	}
	body := decodeJSON(t, resp)
	if uri, _ := body["request_uri"].(string); uri == "" {
		t.Errorf("request_uri missing: %v", body)
	}
}

// TestHandler_NoAuth_Rejected returns 401 invalid_client when the request
// carries no credentials and the client_id is unknown.
func TestHandler_NoAuth_Rejected(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	form := goodAuthorizeForm("unregistered", "https://rp.testkit.invalid/callback")
	resp := f.post(t, form, "", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if body["error"] != "invalid_client" {
		t.Errorf("error=%v want invalid_client", body["error"])
	}
}

func TestHandler_ConfidentialClientIDOnlyRejected(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, _ := f.confidentialClient(t)
	form := goodAuthorizeForm(client.ID, client.RedirectURIs[0])

	resp := f.post(t, form, "", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if body["error"] != "invalid_client" {
		t.Errorf("error=%v want invalid_client", body["error"])
	}
}

// TestHandler_BadSecret_Rejected returns 401 invalid_client and a Basic
// challenge when the request used Basic with a wrong secret.
func TestHandler_BadSecret_Rejected(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, _ := f.confidentialClient(t)
	form := goodAuthorizeForm(client.ID, client.RedirectURIs[0])
	resp := f.post(t, form, client.ID, "wrong-secret")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got == "" {
		t.Errorf("WWW-Authenticate header missing for Basic challenge")
	}
	body := decodeJSON(t, resp)
	if body["error"] != "invalid_client" {
		t.Errorf("error=%v want invalid_client", body["error"])
	}
}

// TestHandler_RequestURIInBody_Rejected enforces RFC 9126 §2.3: the
// /par endpoint MUST NOT accept request_uri in its own body.
func TestHandler_RequestURIInBody_Rejected(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t)
	form := goodAuthorizeForm(client.ID, client.RedirectURIs[0])
	form.Set("request_uri", "urn:ietf:params:oauth:request_uri:abc123")
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if body["error"] != "invalid_request" {
		t.Errorf("error=%v want invalid_request", body["error"])
	}
}

// TestHandler_MissingPKCE_AcceptedUnderNoProfile asserts that an
// authorization request without code_challenge is accepted when no
// profile is active. PKCE is profile-conditional in v0.x: the
// library's overall posture is OAuth 2.1 (PKCE good practice
// everywhere), but the OpenID Connect Basic certification suite
// drives the OP without PKCE because OIDC Core 1.0 predates RFC
// 7636. The test pins the new contract so a regression that
// re-instates the always-required gate becomes loud.
func TestHandler_MissingPKCE_AcceptedUnderNoProfile(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t)
	form := goodAuthorizeForm(client.ID, client.RedirectURIs[0])
	form.Del("code_challenge")
	form.Del("code_challenge_method")
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()

	// The PAR endpoint accepts the request and persists a
	// request_uri; the response is 201 Created with a
	// request_uri / expires_in payload. Profile-mandated PKCE
	// is covered separately by the FAPI 2.0 fixtures.
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status=%d want 201", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if _, ok := body["request_uri"].(string); !ok {
		t.Errorf("response missing request_uri: %v", body)
	}
}

// TestHandler_RedirectURIMismatch_Rejected returns 400 invalid_request
// when the request's redirect_uri is not registered.
func TestHandler_RedirectURIMismatch_Rejected(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t)
	form := goodAuthorizeForm(client.ID, "https://evil.example.com/cb")
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if body["error"] != "invalid_request" {
		t.Errorf("error=%v want invalid_request", body["error"])
	}
}

// TestHandler_ClientIDMismatch_Rejected confirms that a body client_id
// disagreeing with the Basic-auth username is rejected. The authn layer
// catches this case at parsing time, so the wire surface is invalid_client
// (401) rather than the parseAuthorizeRequest single-id-rule path; the
// test pins that contract so a regression that skips the authn check
// (and falls through to invalid_request) becomes loud.
func TestHandler_ClientIDMismatch_Rejected(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t)
	form := goodAuthorizeForm("client-other", client.RedirectURIs[0])
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if body["error"] != "invalid_client" {
		t.Errorf("error=%v want invalid_client", body["error"])
	}
}

// TestHandler_Replay_DistinctURIs verifies that posting the same body
// twice yields two distinct request_uri values (RFC 9126 does not require
// idempotency; the library uses a fresh random URI per request).
func TestHandler_Replay_DistinctURIs(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t)
	form := goodAuthorizeForm(client.ID, client.RedirectURIs[0])
	first := f.post(t, form, client.ID, secret)
	defer first.Body.Close()
	second := f.post(t, form, client.ID, secret)
	defer second.Body.Close()

	if first.StatusCode != http.StatusCreated || second.StatusCode != http.StatusCreated {
		t.Fatalf("statuses=%d,%d want both 201", first.StatusCode, second.StatusCode)
	}
	uri1 := decodeJSON(t, first)["request_uri"].(string)
	uri2 := decodeJSON(t, second)["request_uri"].(string)
	if uri1 == "" || uri2 == "" {
		t.Fatalf("URIs missing: %q, %q", uri1, uri2)
	}
	if uri1 == uri2 {
		t.Errorf("expected distinct URIs, got %q twice", uri1)
	}
}

// TestHandler_BodyTooLarge enforces the 64 KiB ceiling. The test body is
// well above the cap and must be rejected before any client lookup.
func TestHandler_BodyTooLarge(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t)
	// Build a body that is comfortably above the 64 KiB cap by stuffing a
	// long opaque value into the state parameter.
	form := goodAuthorizeForm(client.ID, client.RedirectURIs[0])
	form.Set("state", strings.Repeat("a", 70*1024))
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest && resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want 400 or 413", resp.StatusCode)
	}
}
