package revokeendpoint_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// fixedClock returns a constant Now() reading. The revocation
// handler reads the clock only inside the access-token verifier, so
// a constant value suffices everywhere this file uses it.
type fixedClock struct{ now time.Time }

func (f fixedClock) Now() time.Time { return f.now }

// Compile-time check that the testkit's [op.Clock] satisfies what
// the revokeendpoint Deps expect through the testkit.
var _ op.Clock = fixedClock{}

// fixture bundles a fully-wired testkit Provider with the helpers
// shared across the revocation-endpoint test suite. Mirrors the
// introspectendpoint suite.
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
		testkit.WithOptions(op.WithFeature(feature.Revoke)),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/revoke",
		signer:   tokens.SigningKey{KeyID: prov.SigningKey.KeyID, Signer: prov.SigningKey.Signer},
		clock:    clock,
	}
}

// confidentialClient seeds a confidential client whose secret hash
// matches the supplied plaintext. Mirrors the helper in the
// introspectendpoint and tokenendpoint suites.
func (f *fixture) confidentialClient(tb testing.TB, id string) (*store.Client, string) {
	tb.Helper()
	const secret = "revoke-secret"
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
		ClientID:  "client-conf-revoke",
		IssuedAt:  f.clock.now.Unix(),
		ExpiresAt: f.clock.now.Add(time.Hour).Unix(),
		JTI:       "at-revoke-1",
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
// live record. The caller passes a pre-populated record; saveRefreshToken
// performs only the persistence call.
func (f *fixture) saveRefreshToken(tb testing.TB, rec *store.RefreshToken) {
	tb.Helper()
	if err := f.prov.Store.RefreshTokens().Save(context.Background(), rec); err != nil {
		tb.Fatalf("RefreshTokens.Save: %v", err)
	}
}

// post issues a POST application/x-www-form-urlencoded request with
// the supplied form values. The optional Basic auth pair is set when
// both id and secret are non-empty.
func (f *fixture) post(tb testing.TB, form url.Values, basicID, basicSecret string) *http.Response {
	tb.Helper()
	req, err := http.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		f.endpoint,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basicID != "" {
		req.SetBasicAuth(basicID, basicSecret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		tb.Fatalf("Do: %v", err)
	}
	return resp
}

// decodeJSON parses resp.Body as a JSON object.
func decodeJSON(tb testing.TB, resp *http.Response) map[string]any {
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

// assertCacheControl fails the test if the response is missing the
// no-store header the package stamps unconditionally.
func assertCacheControl(tb testing.TB, resp *http.Response) {
	tb.Helper()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		tb.Errorf("Cache-Control=%q want no-store", got)
	}
}

// assertEmptySuccess fails the test if resp is not the canonical
// RFC 7009 §2.2 success: HTTP 200, empty body, no-store, no
// Content-Type. Centralising the check keeps the success-shape
// contract from drifting across cases.
func assertEmptySuccess(tb testing.TB, resp *http.Response) {
	tb.Helper()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		tb.Fatalf("status=%d want 200; body=%s", resp.StatusCode, dump)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("ReadAll: %v", err)
	}
	if len(body) != 0 {
		tb.Errorf("body length=%d want 0; body=%s", len(body), body)
	}
	if got := resp.Header.Get("Content-Type"); got != "" {
		tb.Errorf("Content-Type=%q want empty (no body, no media)", got)
	}
	assertCacheControl(tb, resp)
}

// TestHandler_GETRejected confirms /revoke refuses GET with 405 +
// Allow.
func TestHandler_GETRejected(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.endpoint, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
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
	resp, err := http.DefaultClient.Do(req)
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

// TestHandler_BadSecret returns 401 invalid_client +
// WWW-Authenticate challenge when Basic auth presents a wrong
// secret.
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
// empty value is a request-level fault not a revocation miss.
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

// TestHandler_JWTAccessToken_Active acknowledges a valid JWT-
// formatted access token with HTTP 200 + empty body. The
// acknowledgement is a no-op (v1.0 does not maintain a denylist),
// but the response still confirms receipt.
func TestHandler_JWTAccessToken_Active(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-jwt-active")
	tok := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = client.ID
	})
	form := url.Values{"token": {tok}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertEmptySuccess(t, resp)
}

// TestHandler_JWTAccessToken_BadSignature returns HTTP 200 + empty
// body when the JWT fails verification. RFC 7009 §2.2 forbids
// leaking the failure mode; the silent miss is the v1.0 posture.
func TestHandler_JWTAccessToken_BadSignature(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-jwt-tampered")
	tok := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) { c.ClientID = client.ID })
	tampered := flipLastSegment(tok)
	form := url.Values{"token": {tampered}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertEmptySuccess(t, resp)
}

// TestHandler_JWTAccessToken_DifferentClient returns HTTP 200 +
// empty body when the authenticated client_id does not match the
// JWT's client_id. Same-client-only is the v1.0 authorization
// posture; the cross-client revoker sees the same response a
// legitimate revoker would.
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
	assertEmptySuccess(t, resp)
}

// TestHandler_RefreshToken_Revokes consumes the chain root for a
// refresh-token revocation. After the call the in-memory store
// either reports the record as gone (ErrNotFound) or stamps
// ConsumedAt; both satisfy the [op/store.RefreshTokenStore.RevokeChain]
// contract.
func TestHandler_RefreshToken_Revokes(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-rt-revoke")
	rec := &store.RefreshToken{
		ID:        "rt-revoke-1",
		ClientID:  client.ID,
		Subject:   "user-rt",
		Scope:     []string{"openid"},
		ExpiresAt: f.clock.now.Add(24 * time.Hour),
		CreatedAt: f.clock.now,
	}
	f.saveRefreshToken(t, rec)
	form := url.Values{"token": {rec.ID}, "token_type_hint": {"refresh_token"}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertEmptySuccess(t, resp)
	assertConsumedOrGone(t, f, rec.ID)
}

// TestHandler_RefreshToken_NotFound returns HTTP 200 + empty body
// when the presented token does not match any stored record.
func TestHandler_RefreshToken_NotFound(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-rt-notfound")
	form := url.Values{"token": {"unknown-token"}, "token_type_hint": {"refresh_token"}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertEmptySuccess(t, resp)
}

// TestHandler_RefreshToken_DifferentClient returns HTTP 200 + empty
// body and leaves the original chain untouched when a different
// client presents the token. Cross-client revocation is silently
// ignored.
func TestHandler_RefreshToken_DifferentClient(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	owner, _ := f.confidentialClient(t, "client-rt-owner")
	caller, callerSecret := f.confidentialClient(t, "client-rt-caller")
	rec := &store.RefreshToken{
		ID:        "rt-cross-1",
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
	assertEmptySuccess(t, resp)
	got, err := f.prov.Store.RefreshTokens().Find(context.Background(), rec.ID)
	if err != nil {
		t.Fatalf("Find after cross-client revoke: %v", err)
	}
	if got == nil || got.ConsumedAt != nil {
		t.Errorf("cross-client revoke mutated record: got=%+v want unconsumed", got)
	}
}

// TestHandler_RefreshToken_RevokesEntireChain seeds a three-
// generation chain and presents the GRANDCHILD's id. After the
// call every record in the chain MUST be consumed or absent — the
// handler walks parent pointers all the way to the root before
// invoking RevokeChain.
func TestHandler_RefreshToken_RevokesEntireChain(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-rt-chain")

	parent := &store.RefreshToken{
		ID:        "rt-parent",
		ClientID:  client.ID,
		Subject:   "user-rt",
		Scope:     []string{"openid"},
		ExpiresAt: f.clock.now.Add(24 * time.Hour),
		CreatedAt: f.clock.now.Add(-2 * time.Minute),
	}
	f.saveRefreshToken(t, parent)

	parentID := parent.ID
	child := &store.RefreshToken{
		ID:        "rt-child",
		ClientID:  client.ID,
		Subject:   "user-rt",
		Scope:     []string{"openid"},
		ParentID:  &parentID,
		ExpiresAt: f.clock.now.Add(24 * time.Hour),
		CreatedAt: f.clock.now.Add(-time.Minute),
	}
	f.saveRefreshToken(t, child)

	childID := child.ID
	grand := &store.RefreshToken{
		ID:        "rt-grand",
		ClientID:  client.ID,
		Subject:   "user-rt",
		Scope:     []string{"openid"},
		ParentID:  &childID,
		ExpiresAt: f.clock.now.Add(24 * time.Hour),
		CreatedAt: f.clock.now,
	}
	f.saveRefreshToken(t, grand)

	form := url.Values{"token": {grand.ID}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertEmptySuccess(t, resp)

	for _, id := range []string{parent.ID, child.ID, grand.ID} {
		assertConsumedOrGone(t, f, id)
	}
}

// TestHandler_HintFallthrough_AccessHintMatchesRefresh confirms
// that a non-JWT-shaped token presented with token_type_hint=
// access_token still falls through to the refresh-token store and
// triggers the chain revocation. RFC 7009 §2.1 requires the search
// to extend across all supported types when the hint misses.
func TestHandler_HintFallthrough_AccessHintMatchesRefresh(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-hint-fallthrough")
	rec := &store.RefreshToken{
		ID:        "rt-hint-fallthrough",
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
	assertEmptySuccess(t, resp)
	assertConsumedOrGone(t, f, rec.ID)
}

// TestHandler_HintFallthrough_RefreshHintMatchesJWT confirms that a
// JWT-shaped token presented with token_type_hint=refresh_token
// still falls through to the JWT verifier. The acknowledgement is
// a no-op but the response is still HTTP 200 + empty body.
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
	assertEmptySuccess(t, resp)
}

// TestHandler_EmptyBody confirms a successful revoke writes a 200
// with body length zero and no Content-Type header. The empty body
// has no media type; setting Content-Type would mislead clients.
func TestHandler_EmptyBody(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-empty-body")
	rec := &store.RefreshToken{
		ID:        "rt-empty-body",
		ClientID:  client.ID,
		Subject:   "user-rt",
		Scope:     []string{"openid"},
		ExpiresAt: f.clock.now.Add(24 * time.Hour),
		CreatedAt: f.clock.now,
	}
	f.saveRefreshToken(t, rec)
	form := url.Values{"token": {rec.ID}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertEmptySuccess(t, resp)
}

// assertConsumedOrGone reports an error when id is still findable
// AND has a nil ConsumedAt. The contract on
// [op/store.RefreshTokenStore.RevokeChain] permits either deletion
// or ConsumedAt-stamping; both satisfy "the token is no longer
// usable". The inmem reference adapter chooses the
// ConsumedAt-stamping branch, but the helper accepts either to
// stay portable as the test suite grows.
func assertConsumedOrGone(tb testing.TB, f *fixture, id string) {
	tb.Helper()
	got, err := f.prov.Store.RefreshTokens().Find(context.Background(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return
		}
		tb.Fatalf("Find(%q): %v", id, err)
	}
	if got == nil {
		return
	}
	if got.ConsumedAt == nil {
		tb.Errorf("Find(%q): record still live (ConsumedAt=nil); want consumed or gone", id)
	}
}

// saveOpaqueAccessToken seeds the testkit's opaque-access-token
// substore with a live record (ADR 0024). The token's raw
// [store.OpaqueAccessToken.ID] is the bearer string the test posts at
// /revoke; the substore hashes it on Save and matches the digest on
// RevokeByID.
func (f *fixture) saveOpaqueAccessToken(tb testing.TB, rec *store.OpaqueAccessToken) {
	tb.Helper()
	if err := f.prov.Store.OpaqueAccessTokens().Save(context.Background(), rec); err != nil {
		tb.Fatalf("OpaqueAccessTokens.Save: %v", err)
	}
}

// TestHandler_OpaqueAccessToken_Revokes flips a live opaque record to
// revoked. After the call the substore reports the record as revoked
// (or absent) and a follow-on /introspect request would collapse
// onto inactive.
func TestHandler_OpaqueAccessToken_Revokes(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-opaque-revoke")
	rec := &store.OpaqueAccessToken{
		ID:        "opaque-revoke-1",
		ClientID:  client.ID,
		Subject:   "user-opaque",
		Scope:     []string{"openid"},
		IssuedAt:  f.clock.now,
		ExpiresAt: f.clock.now.Add(time.Hour),
	}
	f.saveOpaqueAccessToken(t, rec)

	form := url.Values{"token": {rec.ID}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertEmptySuccess(t, resp)

	got, err := f.prov.Store.OpaqueAccessTokens().Find(context.Background(), rec.ID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return
		}
		t.Fatalf("Find after revoke: %v", err)
	}
	if got == nil || !got.Revoked {
		t.Errorf("Find(%q): record still live after revoke; got=%+v", rec.ID, got)
	}
}

// TestHandler_OpaqueAccessToken_NotFound returns HTTP 200 + empty body
// when the presented opaque token does not match any stored record.
// RFC 7009 §2.2 makes the call idempotent: a missing row is treated
// as already-gone.
func TestHandler_OpaqueAccessToken_NotFound(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-opaque-notfound")
	form := url.Values{"token": {"never-issued-opaque"}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertEmptySuccess(t, resp)
}

// TestHandler_OpaqueAccessToken_DifferentClient returns HTTP 200 +
// empty body and leaves the original record untouched when a
// different client presents the token. Cross-client revocation is
// silently ignored (ADR 0024 §S.8).
func TestHandler_OpaqueAccessToken_DifferentClient(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	owner, _ := f.confidentialClient(t, "client-opaque-cross-owner")
	caller, callerSecret := f.confidentialClient(t, "client-opaque-cross-caller")
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
	assertEmptySuccess(t, resp)

	got, err := f.prov.Store.OpaqueAccessTokens().Find(context.Background(), rec.ID)
	if err != nil {
		t.Fatalf("Find after cross-client revoke: %v", err)
	}
	if got == nil || got.Revoked {
		t.Errorf("cross-client revoke mutated record: got=%+v want unrevoked", got)
	}
}

// flipLastSegment returns tok with its signature segment perturbed.
// The function preserves the segment boundaries so the result still
// parses as a JWS but fails signature verification.
func flipLastSegment(tok string) string {
	idx := strings.LastIndex(tok, ".")
	if idx < 0 || idx == len(tok)-1 {
		return tok
	}
	signature := tok[idx+1:]
	first := signature[0]
	var swapped byte = 'A'
	if first == 'A' {
		swapped = 'B'
	}
	return tok[:idx+1] + string(swapped) + signature[1:]
}
