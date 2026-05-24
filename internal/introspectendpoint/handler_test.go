package introspectendpoint_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	httptestutil "github.com/libraz/go-oidc-provider/internal/testutil/httptest"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// fixedClock returns a constant Now() reading. The introspection
// handler reads the clock once per request (for opaque-token expiry
// comparisons) plus once inside the access-token verifier; a constant
// reading suffices everywhere this file uses it.
type fixedClock struct{ now time.Time }

func (f fixedClock) Now() time.Time { return f.now }

// Compile-time check that the testkit's [op.Clock] satisfies what the
// introspectendpoint Deps expect through the testkit.
var _ op.Clock = fixedClock{}

// fixture bundles a fully-wired testkit Provider with the helpers
// shared across the introspection-endpoint test suite. Mirrors the
// parendpoint suite.
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
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithFeature(feature.Introspect)),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/introspect",
		signer:   tokens.SigningKey{KeyID: prov.SigningKey.KeyID, Signer: prov.SigningKey.Signer},
		clock:    clock,
	}
}

// confidentialClient seeds a confidential client whose secret hash
// matches the supplied plaintext. Mirrors the helper in the
// parendpoint and tokenendpoint suites.
func (f *fixture) confidentialClient(tb testing.TB, id string) (*store.Client, string) {
	tb.Helper()
	const secret = "introspect-secret" //nolint:gosec // G101: test fixture credential
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		tb.Fatalf("Argon2id.Hash: %v", err)
	}
	client := f.prov.RegisterClient(tb, testkit.ClientFixture{
		ID:                      id,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		Scopes:                  []string{"openid", "profile", "email"},
	})
	return client, secret
}

// signAccessToken produces a JWS-formatted access token signed with
// the testkit's active key. Callers override individual claims via
// the builder argument; the defaults match the issuer / clock the
// fixture is bound to so the verifier accepts the token.
func (f *fixture) signAccessToken(tb testing.TB, build func(*tokens.AccessTokenClaims)) string {
	tb.Helper()
	c := tokens.AccessTokenClaims{
		Issuer:    f.prov.Issuer,
		Subject:   "user-1",
		Audience:  []string{f.prov.Issuer},
		ClientID:  "client-conf-introspect",
		IssuedAt:  f.clock.now.Unix(),
		ExpiresAt: f.clock.now.Add(time.Hour).Unix(),
		JTI:       "at-introspect-1",
		Scope:     []string{"openid", "profile"},
	}
	if build != nil {
		build(&c)
	}
	jws, err := tokens.SignAccessToken(f.signer, c)
	if err != nil {
		tb.Fatalf("SignAccessToken: %v", err)
	}
	return jws
}

// saveRefreshToken seeds the testkit's refresh-token substore with a
// live record. The returned ID is the opaque token string the test
// posts at /introspect.
func (f *fixture) saveRefreshToken(tb testing.TB, rec *store.RefreshToken) {
	tb.Helper()
	if err := f.prov.Store.RefreshTokens().Save(context.Background(), rec); err != nil {
		tb.Fatalf("RefreshTokens.Save: %v", err)
	}
}

// post issues a POST application/x-www-form-urlencoded request with
// the supplied form values. The optional Basic auth pair is set when
// both id and secret are non-empty. Delegates to the shared
// [httptestutil.PostForm] helper so the wire shape is documented in
// one place.
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
// no-store header RFC 7662 §4 requires.
func assertCacheControl(tb testing.TB, resp *http.Response) {
	tb.Helper()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		tb.Errorf("Cache-Control=%q want no-store", got)
	}
}

// TestHandler_GETRejected confirms /introspect refuses GET with 405 +
// Allow.
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
		strings.NewReader(`{"token":"abc"}`))
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

// TestHandler_NoCredentials returns 401 invalid_client when the
// request has no client authentication.
func TestHandler_NoCredentials(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	form := url.Values{"token": {"some-token"}}
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

func TestHandler_DuplicateTokenRejected(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-dup-token")
	form := url.Values{"token": {"one", "two"}}
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

func TestHandler_DuplicateTokenTypeHintRejected(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-dup-hint")
	form := url.Values{
		"token":           {"some-token"},
		"token_type_hint": {"access_token", "refresh_token"},
	}
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

// TestHandler_BadSecret returns 401 invalid_client + WWW-Authenticate
// challenge when Basic auth presents a wrong secret.
func TestHandler_BadSecret(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, _ := f.confidentialClient(t, "client-bad-secret")
	form := url.Values{"token": {"abc"}}
	resp := f.post(t, form, client.ID, "wrong")
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

// TestHandler_MissingTokenParam returns 400 invalid_request when the
// authenticated request omits the "token" form parameter. The check
// runs AFTER successful client auth — token is structural, so an
// empty value is a request-level fault not an introspection miss.
func TestHandler_MissingTokenParam(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-missing-token")
	form := url.Values{}
	resp := f.post(t, form, client.ID, secret)
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

// TestHandler_JWTAccessToken_Active returns active=true with the
// projected claims for a valid JWT-formatted access token.
func TestHandler_JWTAccessToken_Active(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-jwt-active")
	tok := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = client.ID
		c.Subject = "user-jwt"
		c.Scope = []string{"openid", "profile"}
		c.Audience = []string{f.prov.Issuer}
	})
	form := url.Values{"token": {tok}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, dump)
	}
	body := decodeJSON(t, resp)
	if active, _ := body["active"].(bool); !active {
		t.Fatalf("active=%v want true; body=%v", body["active"], body)
	}
	if body["client_id"] != client.ID {
		t.Errorf("client_id=%v want %q", body["client_id"], client.ID)
	}
	if body["sub"] != "user-jwt" {
		t.Errorf("sub=%v want user-jwt", body["sub"])
	}
	if body["scope"] != "openid profile" {
		t.Errorf("scope=%v want openid profile", body["scope"])
	}
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type=%v want Bearer", body["token_type"])
	}
	if body["iss"] != f.prov.Issuer {
		t.Errorf("iss=%v want %q", body["iss"], f.prov.Issuer)
	}
	assertCacheControl(t, resp)
}

// TestHandler_JWTAccessToken_AuthorizationDetails echoes the RFC 9396
// authorization_details claim onto the introspection response when the
// presented JWT access token carries it (RFC 9396 §9).
func TestHandler_JWTAccessToken_AuthorizationDetails(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-jwt-rar")
	tok := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = client.ID
		c.Subject = "user-jwt-rar"
		c.Scope = []string{"openid"}
		c.Audience = []string{f.prov.Issuer}
		c.AuthorizationDetails = []map[string]any{
			{"type": "payment_initiation", "amount": "100"},
		}
	})
	form := url.Values{"token": {tok}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, dump)
	}
	body := decodeJSON(t, resp)
	if active, _ := body["active"].(bool); !active {
		t.Fatalf("active=%v want true; body=%v", body["active"], body)
	}
	arr, ok := body["authorization_details"].([]any)
	if !ok {
		t.Fatalf("authorization_details not an array: %T", body["authorization_details"])
	}
	if len(arr) != 1 {
		t.Fatalf("authorization_details length=%d want 1", len(arr))
	}
	el, _ := arr[0].(map[string]any)
	if el["type"] != "payment_initiation" {
		t.Errorf("authorization_details[0].type=%v want payment_initiation", el["type"])
	}
}

// TestHandler_JWTAccessToken_Expired returns inactive when the
// presented JWT is past its "exp" + leeway. The HTTP status remains
// 200 — RFC 7662 §2.2 forbids leaking the failure cause through the
// status code.
func TestHandler_JWTAccessToken_Expired(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-jwt-expired")
	tok := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = client.ID
		c.IssuedAt = f.clock.now.Add(-2 * time.Hour).Unix()
		c.ExpiresAt = f.clock.now.Add(-time.Hour).Unix()
	})
	form := url.Values{"token": {tok}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertInactive(t, resp)
}

// TestHandler_JWTAccessToken_BadSignature returns inactive when the
// presented JWT has been tampered with at the signature segment.
func TestHandler_JWTAccessToken_BadSignature(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-jwt-tampered")
	tok := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) { c.ClientID = client.ID })
	tampered := flipLastSegment(tok)
	form := url.Values{"token": {tampered}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertInactive(t, resp)
}

// TestHandler_JWTAccessToken_WrongIssuer returns inactive when the
// JWT's "iss" does not match the OP's configured issuer.
func TestHandler_JWTAccessToken_WrongIssuer(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-jwt-wrong-iss")
	tok := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = client.ID
		c.Issuer = "https://other.example.com"
	})
	form := url.Values{"token": {tok}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertInactive(t, resp)
}

// TestHandler_JWTAccessToken_DifferentClient returns inactive when
// the authenticated client_id does not match the JWT's client_id.
// Same-client-only is the v1.0 authorization posture.
//
// Tracks: CVE-2026-37979 (Keycloak; OIDC token introspection audience
// bypass) — a confidential client must not be able to retrieve claims
// from another client's token merely because it has valid introspection
// credentials.
func TestHandler_JWTAccessToken_DifferentClient(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	owner, _ := f.confidentialClient(t, "client-owner")
	caller, callerSecret := f.confidentialClient(t, "client-caller")
	tok := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = owner.ID
	})
	form := url.Values{"token": {tok}}
	resp := f.post(t, form, caller.ID, callerSecret)
	defer resp.Body.Close()
	assertInactive(t, resp)
}

// TestHandler_RefreshToken_Active returns active=true for a live
// refresh-token record owned by the authenticated client.
func TestHandler_RefreshToken_Active(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-rt-active")
	rec := &store.RefreshToken{
		ID:        "rt-active-1",
		ClientID:  client.ID,
		Subject:   "user-rt",
		Scope:     []string{"openid", "email"},
		ExpiresAt: f.clock.now.Add(24 * time.Hour),
		CreatedAt: f.clock.now,
	}
	f.saveRefreshToken(t, rec)
	form := url.Values{"token": {rec.ID}, "token_type_hint": {"refresh_token"}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if active, _ := body["active"].(bool); !active {
		t.Fatalf("active=%v want true; body=%v", body["active"], body)
	}
	if body["client_id"] != client.ID {
		t.Errorf("client_id=%v want %q", body["client_id"], client.ID)
	}
	if body["sub"] != "user-rt" {
		t.Errorf("sub=%v want user-rt", body["sub"])
	}
	if body["scope"] != "openid email" {
		t.Errorf("scope=%v want openid email", body["scope"])
	}
}

// TestHandler_RefreshToken_Consumed returns inactive when the record
// is still in the store but has been consumed (rotated).
func TestHandler_RefreshToken_Consumed(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-rt-consumed")
	consumed := f.clock.now.Add(-time.Minute)
	rec := &store.RefreshToken{
		ID:         "rt-consumed-1",
		ClientID:   client.ID,
		Subject:    "user-rt",
		Scope:      []string{"openid"},
		ExpiresAt:  f.clock.now.Add(24 * time.Hour),
		CreatedAt:  f.clock.now.Add(-time.Hour),
		ConsumedAt: &consumed,
	}
	f.saveRefreshToken(t, rec)
	form := url.Values{"token": {rec.ID}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertInactive(t, resp)
}

// TestHandler_RefreshToken_Expired returns inactive when the record's
// ExpiresAt is in the past. The inmem store treats expired records
// as ErrNotFound on Find, which the handler collapses onto inactive.
func TestHandler_RefreshToken_Expired(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-rt-expired")
	rec := &store.RefreshToken{
		ID:        "rt-expired-1",
		ClientID:  client.ID,
		Subject:   "user-rt",
		Scope:     []string{"openid"},
		ExpiresAt: f.clock.now.Add(-time.Hour),
		CreatedAt: f.clock.now.Add(-2 * time.Hour),
	}
	f.saveRefreshToken(t, rec)
	form := url.Values{"token": {rec.ID}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertInactive(t, resp)
}

// TestHandler_RefreshToken_NotFound returns inactive when the
// presented token does not match any stored record.
func TestHandler_RefreshToken_NotFound(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-rt-notfound")
	form := url.Values{"token": {"unknown-token"}, "token_type_hint": {"refresh_token"}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertInactive(t, resp)
}

// TestHandler_RefreshToken_DifferentClient returns inactive when the
// authenticated client does not own the refresh-token record.
func TestHandler_RefreshToken_DifferentClient(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	owner, _ := f.confidentialClient(t, "client-rt-owner")
	caller, callerSecret := f.confidentialClient(t, "client-rt-caller")
	rec := &store.RefreshToken{
		ID:        "rt-other-1",
		ClientID:  owner.ID,
		Subject:   "user-rt",
		Scope:     []string{"openid"},
		ExpiresAt: f.clock.now.Add(24 * time.Hour),
		CreatedAt: f.clock.now,
	}
	f.saveRefreshToken(t, rec)
	form := url.Values{"token": {rec.ID}}
	resp := f.post(t, form, caller.ID, callerSecret)
	defer resp.Body.Close()
	assertInactive(t, resp)
}

// TestHandler_HintFallthrough_AccessToHintMatchesRefresh confirms
// that a non-JWT-shaped token presented with token_type_hint=
// access_token still falls through to the refresh-token store. RFC
// 7662 §2.1 requires the search to extend across all supported types
// when the hint misses.
func TestHandler_HintFallthrough_AccessToHintMatchesRefresh(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-hint-fallthrough")
	rec := &store.RefreshToken{
		ID:        "rt-fallthrough-1",
		ClientID:  client.ID,
		Subject:   "user-rt",
		Scope:     []string{"openid"},
		ExpiresAt: f.clock.now.Add(24 * time.Hour),
		CreatedAt: f.clock.now,
	}
	f.saveRefreshToken(t, rec)
	form := url.Values{"token": {rec.ID}, "token_type_hint": {"access_token"}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if active, _ := body["active"].(bool); !active {
		t.Fatalf("active=%v want true; body=%v", body["active"], body)
	}
}

// TestHandler_HintFallthrough_RefreshHintMatchesJWT confirms that a
// JWT-shaped token presented with token_type_hint=refresh_token
// still falls through to the JWT verifier on opaque miss.
func TestHandler_HintFallthrough_RefreshHintMatchesJWT(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-hint-jwt-fallthrough")
	tok := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = client.ID
	})
	form := url.Values{"token": {tok}, "token_type_hint": {"refresh_token"}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if active, _ := body["active"].(bool); !active {
		t.Fatalf("active=%v want true; body=%v", body["active"], body)
	}
}

// TestHandler_InactiveResponseShape confirms that an inactive
// response carries ONLY the "active" member per RFC 7662 §2.2.
func TestHandler_InactiveResponseShape(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-inactive-shape")
	form := url.Values{"token": {"never-issued"}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	body := decodeJSON(t, resp)
	if len(body) != 1 {
		t.Errorf("inactive response has %d members; want exactly 1; body=%v", len(body), body)
	}
	if active, _ := body["active"].(bool); active {
		t.Errorf("active=true in inactive response; body=%v", body)
	}
}

// assertInactive fails the test when resp does not carry a 200
// status with the canonical {"active": false} body.
func assertInactive(tb testing.TB, resp *http.Response) {
	tb.Helper()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		tb.Fatalf("status=%d want 200; body=%s", resp.StatusCode, dump)
	}
	body := decodeJSON(tb, resp)
	if active, _ := body["active"].(bool); active {
		tb.Errorf("active=true in inactive response; body=%v", body)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		tb.Errorf("Cache-Control=%q want no-store", got)
	}
}

// saveOpaqueAccessToken seeds the testkit's opaque-access-token
// substore with a live record. The caller passes a pre-populated
// record; saveOpaqueAccessToken performs only the persistence call.
// The token's raw [store.OpaqueAccessToken.ID] is the bearer string
// the test posts at /introspect; the substore hashes it on Save and
// matches the digest on Find.
func (f *fixture) saveOpaqueAccessToken(tb testing.TB, rec *store.OpaqueAccessToken) {
	tb.Helper()
	if err := f.prov.Store.OpaqueAccessTokens().Save(context.Background(), rec); err != nil {
		tb.Fatalf("OpaqueAccessTokens.Save: %v", err)
	}
}

// TestHandler_OpaqueAccessToken_Active returns active=true with the
// projected claims for a live opaque-format access token (ADR 0024).
// The test pins the cnf, scope, audience, and ACR / AMR projections
// so a future refactor that drops a field surfaces here.
func TestHandler_OpaqueAccessToken_Active(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-opaque-active")
	rec := &store.OpaqueAccessToken{
		ID:                 "opaque-active-1",
		ClientID:           client.ID,
		Subject:            "user-opaque",
		Scope:              []string{"openid", "profile"},
		Audience:           "https://api.example.com",
		ACR:                "urn:mace:incommon:iap:silver",
		AMR:                []string{"pwd", "mfa"},
		AuthTime:           f.clock.now.Add(-5 * time.Minute),
		IssuedAt:           f.clock.now,
		ExpiresAt:          f.clock.now.Add(time.Hour),
		DPoPJKT:            "test-jkt",
		MTLSCertThumbprint: "test-x5t",
	}
	f.saveOpaqueAccessToken(t, rec)

	form := url.Values{"token": {rec.ID}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, dump)
	}
	body := decodeJSON(t, resp)
	if active, _ := body["active"].(bool); !active {
		t.Fatalf("active=%v want true; body=%v", body["active"], body)
	}
	if body["client_id"] != client.ID {
		t.Errorf("client_id=%v want %q", body["client_id"], client.ID)
	}
	if body["sub"] != "user-opaque" {
		t.Errorf("sub=%v want user-opaque", body["sub"])
	}
	if body["scope"] != "openid profile" {
		t.Errorf("scope=%v want \"openid profile\"", body["scope"])
	}
	if body["token_type"] != "Bearer" {
		t.Errorf("token_type=%v want Bearer", body["token_type"])
	}
	aud, ok := body["aud"].([]any)
	if !ok || len(aud) != 1 || aud[0] != "https://api.example.com" {
		t.Errorf("aud=%v want [https://api.example.com]", body["aud"])
	}
	if body["acr"] != "urn:mace:incommon:iap:silver" {
		t.Errorf("acr=%v", body["acr"])
	}
	cnf, ok := body["cnf"].(map[string]any)
	if !ok {
		t.Fatalf("cnf=%v not a map; body=%v", body["cnf"], body)
	}
	if cnf["jkt"] != "test-jkt" {
		t.Errorf("cnf.jkt=%v want test-jkt", cnf["jkt"])
	}
	if cnf["x5t#S256"] != "test-x5t" {
		t.Errorf("cnf.x5t#S256=%v want test-x5t", cnf["x5t#S256"])
	}
	assertCacheControl(t, resp)
}

// TestHandler_OpaqueAccessToken_Revoked returns inactive when the
// stored opaque record has been flipped to revoked.
func TestHandler_OpaqueAccessToken_Revoked(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-opaque-revoked")
	rec := &store.OpaqueAccessToken{
		ID:        "opaque-revoked-1",
		ClientID:  client.ID,
		Subject:   "user-opaque",
		Scope:     []string{"openid"},
		IssuedAt:  f.clock.now,
		ExpiresAt: f.clock.now.Add(time.Hour),
	}
	f.saveOpaqueAccessToken(t, rec)
	if err := f.prov.Store.OpaqueAccessTokens().RevokeByID(context.Background(), rec.ID); err != nil {
		t.Fatalf("RevokeByID: %v", err)
	}
	form := url.Values{"token": {rec.ID}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertInactive(t, resp)
}

// TestHandler_OpaqueAccessToken_Expired returns inactive when the
// stored opaque record's ExpiresAt is in the past relative to the
// fixture clock.
func TestHandler_OpaqueAccessToken_Expired(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-opaque-expired")
	rec := &store.OpaqueAccessToken{
		ID:        "opaque-expired-1",
		ClientID:  client.ID,
		Subject:   "user-opaque",
		Scope:     []string{"openid"},
		IssuedAt:  f.clock.now.Add(-2 * time.Hour),
		ExpiresAt: f.clock.now.Add(-time.Hour),
	}
	f.saveOpaqueAccessToken(t, rec)
	form := url.Values{"token": {rec.ID}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertInactive(t, resp)
}

// TestHandler_OpaqueAccessToken_DifferentClient returns inactive when
// the authenticated client_id does not match the record's ClientID.
// Same-client-only is the v1.0 authorization posture (ADR 0024 §S.8).
//
// Tracks: CVE-2026-37979 (Keycloak; OIDC token introspection audience
// bypass). Opaque access-token introspection follows the same inactive
// collapse as JWT access tokens so cross-client callers learn neither
// token existence nor projected claims.
func TestHandler_OpaqueAccessToken_DifferentClient(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	owner, _ := f.confidentialClient(t, "client-opaque-owner")
	caller, callerSecret := f.confidentialClient(t, "client-opaque-caller")
	rec := &store.OpaqueAccessToken{
		ID:        "opaque-cross-1",
		ClientID:  owner.ID,
		Subject:   "user-opaque",
		Scope:     []string{"openid"},
		IssuedAt:  f.clock.now,
		ExpiresAt: f.clock.now.Add(time.Hour),
	}
	f.saveOpaqueAccessToken(t, rec)
	form := url.Values{"token": {rec.ID}}
	resp := f.post(t, form, caller.ID, callerSecret)
	defer resp.Body.Close()
	assertInactive(t, resp)
}

// TestHandler_OpaqueAccessToken_NotFound returns inactive when the
// presented token does not match any stored record.
func TestHandler_OpaqueAccessToken_NotFound(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-opaque-notfound")
	form := url.Values{"token": {"never-issued-opaque"}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertInactive(t, resp)
}

// flipLastSegment returns tok with its signature segment perturbed.
// The function preserves the segment boundaries so the result still
// parses as a JWS but fails signature verification.
func flipLastSegment(tok string) string {
	idx := strings.LastIndex(tok, ".")
	if idx < 0 || idx == len(tok)-1 {
		return tok
	}
	// Flip the first character of the signature segment to a
	// different base64url character. The substitution is
	// deterministic (A->B, otherwise->A) so the test stays
	// reproducible across runs.
	signature := tok[idx+1:]
	first := signature[0]
	var swapped byte = 'A'
	if first == 'A' {
		swapped = 'B'
	}
	return tok[:idx+1] + string(swapped) + signature[1:]
}
