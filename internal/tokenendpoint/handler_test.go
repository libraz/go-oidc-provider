package tokenendpoint_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/keys"
	httptestutil "github.com/libraz/go-oidc-provider/internal/testutil/httptest"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// jsonUnmarshal aliases [json.Unmarshal] so the helper-suite tests can
// reach a JSON decoder without each one importing encoding/json.
func jsonUnmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }

// decodeBase64URL decodes a base64url-no-pad string.
func decodeBase64URL(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func paymentAuthorizationDetailsOption() op.Option {
	return op.WithAuthorizationDetailTypes(op.AuthorizationDetailType{
		Type: "payment",
		Validate: func(_ context.Context, el map[string]any, _ *store.Client) error {
			if _, ok := el["amount"].(string); !ok {
				return errors.New("amount is required")
			}
			return nil
		},
	})
}

// mustKeySet builds a [*keys.Set] from the testkit's active signer so
// tests can hand it to a [tokens.AccessTokenVerifier]. The conversion
// is required because [op.Provider] does not expose its keys directly;
// instead the testkit publishes the signer and tests reconstruct.
func mustKeySet(tb testing.TB, prov *testkit.Provider) *keys.Set {
	tb.Helper()
	set, err := keys.NewSet([]keys.Entry{{KeyID: prov.SigningKey.KeyID, Signer: prov.SigningKey.Signer}})
	if err != nil {
		tb.Fatalf("keys.NewSet: %v", err)
	}
	return set
}

// fixedClock returns a constant Now() reading. Tests inject it through
// the testkit so the OP's exchanger and the test's wall-clock view stay
// aligned even for code paths that depend on expiry.
type fixedClock struct{ now time.Time }

func (f fixedClock) Now() time.Time { return f.now }

// fixture bundles a fully-wired testkit Provider with the helpers shared
// across the token-endpoint test suite.
type fixture struct {
	prov     *testkit.Provider
	endpoint string
	signer   tokens.SigningKey
	clock    fixedClock
}

// newFixture builds a fixture pinned to a deterministic clock. The
// 2026-04-26 anchor matches the existing test suites and the docs'
// "today" baseline.
func newFixture(tb testing.TB) *fixture {
	return newFixtureWithOptions(tb)
}

func newFixtureWithOptions(tb testing.TB, opts ...op.Option) *fixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	provOpts := []testkit.Option{testkit.WithClock(clock)}
	if len(opts) > 0 {
		provOpts = append(provOpts, testkit.WithOptions(opts...))
	}
	prov := testkit.NewProvider(tb, provOpts...)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		signer:   tokens.SigningKey{KeyID: prov.SigningKey.KeyID, Signer: prov.SigningKey.Signer},
		clock:    clock,
	}
}

// pkcePair returns a PKCE verifier paired with the SHA-256 base64url
// challenge derived from it. The verifier length (64) sits inside the
// 43..128 RFC 7636 §4.1 bound.
func pkcePair() (verifier, challenge string) {
	verifier = "test-verifier-test-verifier-test-verifier-test-verifier-1234567"
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

// confidentialClientFixture seeds a confidential client whose secret
// hash matches the supplied plaintext, returning the registered client
// and the plaintext for callers to thread through Basic auth.
func (f *fixture) confidentialClientFixture(tb testing.TB) (*store.Client, string) {
	tb.Helper()
	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		tb.Fatalf("Argon2id.Hash: %v", err)
	}
	client := f.prov.RegisterClient(tb, testkit.ClientFixture{
		ID:                      "client-conf",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	return client, secret
}

// publicClientFixture seeds a public client (PKCE-only).
func (f *fixture) publicClientFixture(tb testing.TB) *store.Client {
	tb.Helper()
	return f.prov.RegisterClient(tb, testkit.ClientFixture{
		ID:           "client-pub",
		PublicClient: true,
	})
}

// seedAuthCode persists an [store.AuthorizationCode] directly so tests
// can drive the token endpoint without first running the authorization
// endpoint. The returned code value is the "code" parameter clients
// present at /token.
func (f *fixture) seedAuthCode(tb testing.TB, ac *store.AuthorizationCode) {
	tb.Helper()
	if ac.ExpiresAt.IsZero() {
		ac.ExpiresAt = f.clock.now.Add(time.Minute)
	}
	if ac.CreatedAt.IsZero() {
		ac.CreatedAt = f.clock.now
	}
	if err := f.prov.Store.AuthorizationCodes().Save(context.Background(), ac); err != nil {
		tb.Fatalf("AuthorizationCodes.Save: %v", err)
	}
}

// seedRefreshToken persists a [store.RefreshToken] directly.
func (f *fixture) seedRefreshToken(tb testing.TB, rt *store.RefreshToken) {
	tb.Helper()
	if rt.ExpiresAt.IsZero() {
		rt.ExpiresAt = f.clock.now.Add(time.Hour)
	}
	if rt.CreatedAt.IsZero() {
		rt.CreatedAt = f.clock.now
	}
	if err := f.prov.Store.RefreshTokens().Save(context.Background(), rt); err != nil {
		tb.Fatalf("RefreshTokens.Save: %v", err)
	}
}

// seedGrant persists a [store.Grant] so the handler's auth_time lookup
// has something to read.
func (f *fixture) seedGrant(tb testing.TB, g *store.Grant) {
	tb.Helper()
	if g.UpdatedAt.IsZero() {
		g.UpdatedAt = f.clock.now
	}
	if g.CreatedAt.IsZero() {
		g.CreatedAt = f.clock.now
	}
	if err := f.prov.Store.Grants().Save(context.Background(), g); err != nil {
		tb.Fatalf("Grants.Save: %v", err)
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
	if got := resp.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		tb.Errorf("X-Content-Type-Options=%q want nosniff", got)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json; charset=utf-8" {
		tb.Errorf("Content-Type=%q want application/json; charset=utf-8", got)
	}
}

// TestHandler_GETRejected confirms the endpoint refuses non-POST
// methods and surfaces the Allow header.
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

// TestHandler_NoBody returns 400 invalid_request when the body is empty
// (no grant_type means no grant_type, even on the public-client path).
func TestHandler_NoBody(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	resp := f.post(t, url.Values{}, "", "")
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

// TestHandler_WrongContentType refuses non-form bodies with 400
// invalid_request.
func TestHandler_WrongContentType(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		f.endpoint,
		strings.NewReader(`{"grant_type":"authorization_code"}`),
	)
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

// TestHandler_BodyTooLarge pins the 64 KiB body-size ceiling the
// endpoint installs via endpointsupport.LimitFormBody before ParseForm
// runs. A body comfortably above the cap must be rejected as
// invalid_request before grant dispatch — the same wire shape the
// endpoint produced when it wrapped r.Body in http.MaxBytesReader
// directly, prior to routing through the shared limiter.
func TestHandler_BodyTooLarge(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", strings.Repeat("a", 70*1024))
	resp := f.post(t, form, "", "")
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

// TestHandler_UnknownGrantType yields unsupported_grant_type per
// RFC 6749 §5.2. The chosen grant_type is a deliberately bogus value
// that no RFC defines, so the test stays green even as future
// dispatch arms (device_code, token_exchange, etc.) land.
func TestHandler_UnknownGrantType(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	form := url.Values{}
	form.Set("grant_type", "urn:example:not-a-real-grant-type")
	resp := f.post(t, form, "", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if body["error"] != "unsupported_grant_type" {
		t.Errorf("error=%v want unsupported_grant_type", body["error"])
	}
	assertCacheControl(t, resp)
}

// TestHandler_DuplicateSingleValuedParameter pins the rule that
// every single-valued parameter the dispatcher / grant handlers /
// shared client-auth parser read MUST be rejected when it appears
// more than once. The check fires before grant_type dispatch so the
// rejection is uniform regardless of which grant the request claims.
//
// The matrix exercises every name in
// [tokenendpoint.tokenSingleValuedParams] (asserted indirectly: a
// regression that drops a row stops failing this row but the wire
// shape it allows is exactly the parser-confusion vector this
// guard exists to close). The list itself is held to the package's
// actual form reads by a source-level guard in the package tests, so
// a parameter that reaches a grant handler without a row here fails
// there rather than passing unnoticed.
func TestHandler_DuplicateSingleValuedParameter(t *testing.T) {
	t.Parallel()

	// Every standard credential / dispatch parameter the spec marks
	// single-valued. "resource" is intentionally absent — RFC 8707
	// §2 lets it repeat — and a separate row below pins that posture.
	cases := []struct {
		name  string
		param string
	}{
		{"grant_type", "grant_type"},
		{"client_id", "client_id"},
		{"client_secret", "client_secret"},
		{"client_assertion_type", "client_assertion_type"},
		{"client_assertion", "client_assertion"},
		{"code", "code"},
		{"redirect_uri", "redirect_uri"},
		{"code_verifier", "code_verifier"},
		{"refresh_token", "refresh_token"},
		{"scope", "scope"},
		{"device_code", "device_code"},
		{"auth_req_id", "auth_req_id"},
		{"authorization_details", "authorization_details"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			form := url.Values{}
			// Always set a valid grant_type so the duplicate row that is
			// not grant_type cannot bypass the gate by being rejected
			// downstream.
			form.Set("grant_type", "authorization_code")
			form.Add(tc.param, "value-1")
			form.Add(tc.param, "value-2")
			resp := f.post(t, form, "", "")
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status=%d want 400", resp.StatusCode)
			}
			body := decodeJSON(t, resp)
			if body["error"] != "invalid_request" {
				t.Errorf("error=%v want invalid_request", body["error"])
			}
			if desc, _ := body["error_description"].(string); !strings.Contains(desc, tc.param) {
				t.Errorf("error_description=%q want it to name %q", desc, tc.param)
			}
			assertCacheControl(t, resp)
		})
	}
}

// TestHandler_DuplicateResourceAccepted pins the dual to the
// single-valued matrix: RFC 8707 §2 explicitly permits the "resource"
// parameter to repeat, so the dispatcher MUST forward the request to
// the grant handler. We use an unknown grant_type so the duplicate
// "resource" survives long enough to land on the
// unsupported_grant_type wire envelope (which is downstream of the
// duplicate gate).
func TestHandler_DuplicateResourceAccepted(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	form := url.Values{}
	form.Set("grant_type", "urn:example:not-a-real-grant-type")
	form.Add("resource", "https://api-a.example.com")
	form.Add("resource", "https://api-b.example.com")
	resp := f.post(t, form, "", "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if body["error"] != "unsupported_grant_type" {
		t.Errorf("error=%v want unsupported_grant_type (duplicate-resource MUST pass the gate)", body["error"])
	}
}

// Compile-time check that op.Clock and the tokenendpoint Clock are
// structurally compatible.
var _ interface{ Now() time.Time } = fixedClock{}
