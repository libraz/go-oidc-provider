package userinfo_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/subject"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// fixedClock returns a constant Now() reading. The userinfo handler reads
// the clock through the access-token verifier, which calls Now() at most
// once per Verify; a constant suffices everywhere this file uses it.
type fixedClock struct{ now time.Time }

func (f fixedClock) Now() time.Time { return f.now }

// userInfoFixture bundles a fully-wired testkit Provider with the
// supporting helpers the tests in this file need: the URL of the
// /userinfo endpoint, a tokens.SigningKey reachable from internal/tokens,
// and the fake clock the OP shares so token expiry is deterministic.
type userInfoFixture struct {
	prov     *testkit.Provider
	endpoint string
	signer   tokens.SigningKey
	clock    fixedClock
}

func newUserInfoFixture(tb testing.TB) *userInfoFixture {
	return newUserInfoFixtureWithOptions(tb)
}

func newUserInfoFixtureWithOptions(tb testing.TB, opts ...op.Option) *userInfoFixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb, testkit.WithClock(clock), testkit.WithOptions(opts...))
	seedTokenClient(tb, prov)
	return &userInfoFixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/userinfo",
		// op.SigningKey and tokens.SigningKey share the same shape; the
		// boundary copy is intentional so this test does not depend on
		// any internal converter.
		signer: tokens.SigningKey{KeyID: prov.SigningKey.KeyID, Signer: prov.SigningKey.Signer},
		clock:  clock,
	}
}

// seedTokenClient registers the client the fixture's signed tokens name.
// /userinfo requires the token's client to still exist, so without this
// every fixture would be describing a state the OP cannot produce: a
// token bearing a client_id the token endpoint could not have issued to.
func seedTokenClient(tb testing.TB, prov *testkit.Provider) {
	tb.Helper()
	prov.RegisterClient(tb, testkit.ClientFixture{ID: fixtureClientID})
}

// fixtureClientID is the client_id every fixture-signed access token
// carries; see signAccessToken.
const fixtureClientID = "client-1"

// putUser seeds the testkit store with a user record so /userinfo has
// something to return. The test owns the claim map; the substore takes
// a defensive copy.
func (f *userInfoFixture) putUser(tb testing.TB, sub string, claims map[string]any) {
	tb.Helper()
	f.prov.Store.PutUser(context.Background(), &store.User{Subject: sub, Claims: claims})
}

// signAccessToken produces a JWS-formatted access token signed with the
// testkit's active key. Callers override individual claims via the
// builder argument; the defaults match the issuer / clock the fixture
// is bound to so the verifier accepts the token.
func (f *userInfoFixture) signAccessToken(tb testing.TB, build func(*tokens.AccessTokenClaims)) string {
	tb.Helper()
	c := tokens.AccessTokenClaims{
		Issuer:    f.prov.Issuer,
		Subject:   "user-1",
		Audience:  []string{f.prov.Issuer},
		ClientID:  fixtureClientID,
		IssuedAt:  f.clock.now.Unix(),
		ExpiresAt: f.clock.now.Add(time.Hour).Unix(),
		JTI:       "at-1",
		Scope:     []string{"openid", "email"},
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

// doRequest issues an HTTP request to /userinfo and returns the
// response. The request carries a request-scoped context so the test
// satisfies the noctx lint and cancels in-flight calls on failure.
//
// The URL targeted by req is the testkit's httptest server, never an
// attacker-controlled host; the gosec SSRF taint check is suppressed
// because the test is exercising the handler against a known-good
// server bound to a localhost listener.
func (f *userInfoFixture) doRequest(tb testing.TB, req *http.Request) *http.Response {
	tb.Helper()
	resp, err := f.prov.HTTPClient(nil).Do(req)
	if err != nil {
		tb.Fatalf("Do: %v", err)
	}
	return resp
}

// newGet builds a GET /userinfo request with the supplied bearer token.
// An empty token elides the Authorization header so the handler sees the
// "no credentials" case.
func (f *userInfoFixture) newGet(tb testing.TB, token string) *http.Request {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.endpoint, http.NoBody)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return req
}

// newGetDPoP builds a GET /userinfo request presenting the token under the
// RFC 9449 §7.1 "DPoP" authentication scheme, as a DPoP-bound access token
// MUST be. The caller still sets the "DPoP" proof header separately.
func (f *userInfoFixture) newGetDPoP(tb testing.TB, token string) *http.Request {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.endpoint, http.NoBody)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "DPoP "+token)
	}
	return req
}

func TestHandler_HappyPath_OpenIDEmail(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{
		"email":          "alice@example.com",
		"email_verified": true,
		"phone_number":   "+1-555-0100",
		"address":        map[string]any{"street_address": "1 Main St"},
		"name":           "Alice Example",
	})
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Scope = []string{"openid", "email"}
	})
	resp := f.doRequest(t, f.newGet(t, token))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type=%q want application/json", got)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store, private" {
		t.Errorf("Cache-Control=%q want no-store, private", got)
	}

	body := decodeBody(t, resp)
	if body["sub"] != "user-1" {
		t.Errorf("sub=%v want user-1", body["sub"])
	}
	if body["email"] != "alice@example.com" {
		t.Errorf("email=%v", body["email"])
	}
	if body["email_verified"] != true {
		t.Errorf("email_verified=%v want true", body["email_verified"])
	}
	if _, ok := body["phone_number"]; ok {
		t.Errorf("phone_number must NOT be released without phone scope")
	}
	if _, ok := body["address"]; ok {
		t.Errorf("address must NOT be released without address scope")
	}
	if _, ok := body["name"]; ok {
		t.Errorf("name must NOT be released without profile scope")
	}
}

func TestHandler_PairwiseJWTWithoutGrantIDRejected(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixtureWithOptions(t, op.WithPairwiseSubject([]byte("userinfo-pairwise-fixed-salt-32b")))
	// A second client, registered as pairwise, rather than a redefinition
	// of the fixture's default: the token below names it explicitly, so
	// the pairwise attribute under test is visible at the call site.
	const pairwiseClientID = "client-1-pairwise"
	f.prov.RegisterClient(t, testkit.ClientFixture{
		ID:          pairwiseClientID,
		SubjectType: "pairwise",
	})
	f.putUser(t, "pairwise-user-1", map[string]any{
		"email": "pairwise@example.com",
	})
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.ClientID = pairwiseClientID
		c.Subject = "pairwise-user-1"
		c.GrantID = ""
		c.Scope = []string{"openid", "email"}
	})

	resp := f.doRequest(t, f.newGet(t, token))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	got := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(got, `error="invalid_token"`) {
		t.Fatalf("WWW-Authenticate=%q want invalid_token", got)
	}
	if !strings.Contains(got, "The access token is invalid") {
		t.Fatalf("WWW-Authenticate=%q must use the generic invalid description", got)
	}
	if strings.Contains(got, "grant unknown") {
		t.Fatalf("WWW-Authenticate=%q must not expose grant existence", got)
	}
}

func TestHandler_ProfileScope_ReleasesProfileClaims(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{
		"name":        "Alice Example",
		"given_name":  "Alice",
		"family_name": "Example",
		"email":       "alice@example.com",
	})
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Scope = []string{"openid", "profile"}
	})
	resp := f.doRequest(t, f.newGet(t, token))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeBody(t, resp)
	for _, name := range []string{"name", "given_name", "family_name"} {
		if _, ok := body[name]; !ok {
			t.Errorf("%s must be released under profile scope", name)
		}
	}
	if _, ok := body["email"]; ok {
		t.Errorf("email must NOT be released without email scope")
	}
}

func TestHandler_NoAuthorization_ReturnsBareChallenge(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	resp := f.doRequest(t, f.newGet(t, ""))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	got := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(got, "Bearer ") {
		t.Fatalf("WWW-Authenticate=%q must start with Bearer", got)
	}
	if strings.Contains(got, "error=") {
		t.Fatalf("WWW-Authenticate=%q must NOT carry error= for missing-credentials path", got)
	}
	assertNoClaimLeak(t, resp)
}

func TestHandler_BadToken_ReturnsInvalidToken(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	// Sign with an unrelated key so the verifier cannot find the kid.
	other := testkit.NewProvider(t)
	otherSigner := tokens.SigningKey{KeyID: other.SigningKey.KeyID, Signer: other.SigningKey.Signer}
	jws, err := tokens.SignAccessToken(otherSigner, tokens.AccessTokenClaims{
		Issuer:    f.prov.Issuer,
		Subject:   "user-1",
		Audience:  []string{f.prov.Issuer},
		ClientID:  fixtureClientID,
		IssuedAt:  f.clock.now.Unix(),
		ExpiresAt: f.clock.now.Add(time.Hour).Unix(),
		JTI:       "rogue",
		Scope:     []string{"openid"},
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}

	resp := f.doRequest(t, f.newGet(t, jws))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	got := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(got, `error="invalid_token"`) {
		t.Fatalf("WWW-Authenticate=%q must declare invalid_token", got)
	}
	if !strings.Contains(got, "The access token is invalid") {
		t.Fatalf("WWW-Authenticate=%q must use the generic invalid description", got)
	}
	assertNoClaimLeak(t, resp)
}

func TestHandler_ExpiredToken_DescribesExpiry(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{"email": "alice@example.com"})
	// Issue a token whose exp is well behind the OP clock even after the
	// 30-second leeway in op.defaultUserInfoLeeway.
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.IssuedAt = f.clock.now.Add(-2 * time.Hour).Unix()
		c.ExpiresAt = f.clock.now.Add(-time.Hour).Unix()
	})
	resp := f.doRequest(t, f.newGet(t, token))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	got := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(got, `error="invalid_token"`) {
		t.Fatalf("WWW-Authenticate=%q must declare invalid_token", got)
	}
	if !strings.Contains(got, "The access token expired") {
		t.Fatalf("WWW-Authenticate=%q must distinguish the expired case", got)
	}
	assertNoClaimLeak(t, resp)
}

func TestHandler_POST_BodyToken(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{"email": "alice@example.com", "email_verified": true})
	token := f.signAccessToken(t, nil)

	body := strings.NewReader("access_token=" + token)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, f.endpoint, body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp := f.doRequest(t, req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	out := decodeBody(t, resp)
	if out["sub"] != "user-1" {
		t.Errorf("sub=%v want user-1", out["sub"])
	}
}

func TestHandler_POST_BothChannelsRejected(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	token := f.signAccessToken(t, nil)

	body := strings.NewReader("access_token=" + token)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, f.endpoint, body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	resp := f.doRequest(t, req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	got := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(got, `error="invalid_request"`) {
		t.Fatalf("WWW-Authenticate=%q must declare invalid_request", got)
	}
	assertNoClaimLeak(t, resp)
}

func TestHandler_QueryStringToken_Ignored(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{"email": "alice@example.com"})
	token := f.signAccessToken(t, nil)

	target := f.endpoint + "?access_token=" + token
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp := f.doRequest(t, req)
	defer resp.Body.Close()

	// RFC 9700 §2.4: query-string credentials must be ignored. The handler
	// MUST therefore see the request as un-authenticated and emit the
	// bare-challenge 401.
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 (query-string token must be ignored)", resp.StatusCode)
	}
	got := resp.Header.Get("WWW-Authenticate")
	if strings.Contains(got, "error=") {
		t.Fatalf("WWW-Authenticate=%q must be the bare challenge — query token must not auth nor invalidate", got)
	}
	assertNoClaimLeak(t, resp)
}

func TestHandler_SubjectDeleted_ReturnsInvalidToken(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	// Token claims subject "ghost", but no user with that subject is
	// seeded into the store.
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Subject = "ghost"
	})
	resp := f.doRequest(t, f.newGet(t, token))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	got := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(got, `error="invalid_token"`) {
		t.Fatalf("WWW-Authenticate=%q must declare invalid_token", got)
	}
	if !strings.Contains(got, "The access token is invalid") {
		t.Fatalf("WWW-Authenticate=%q must use the generic invalid description", got)
	}
	if strings.Contains(got, "subject unknown") {
		t.Fatalf("WWW-Authenticate=%q must not expose subject existence", got)
	}
	assertNoClaimLeak(t, resp)
}

// TestHandler_DeletedClientRevokesItsAccessToken is the endpoint-side
// half of the client-deletion cascade. A JWT access token carries no row
// to revoke, and the tombstone substore is keyed on grant_id, so a
// deletion — which yields no list of grants — cannot reach it that way.
// Requiring the client to still be registered is what makes the deletion
// take effect here.
//
// The token is minted before the deletion and presented after, so a
// handler that only checked the client at issuance would still serve it.
func TestHandler_DeletedClientRevokesItsAccessToken(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	f.putUser(t, "user-1", map[string]any{"email": "alice@example.com"})
	token := f.signAccessToken(t, nil)

	// The same token is served before the deletion, so the 401 below
	// cannot be blamed on anything else about the request.
	before := f.doRequest(t, f.newGet(t, token))
	before.Body.Close()
	if before.StatusCode != http.StatusOK {
		t.Fatalf("status before deletion=%d want 200", before.StatusCode)
	}

	if err := f.prov.Store.DeleteClient(context.Background(), fixtureClientID); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}

	resp := f.doRequest(t, f.newGet(t, token))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status after deletion=%d want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, `error="invalid_token"`) {
		t.Fatalf("WWW-Authenticate=%q must declare invalid_token", got)
	}
	assertNoClaimLeak(t, resp)
}

func TestHandler_PUT_ReturnsMethodNotAllowed(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, f.endpoint, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp := f.doRequest(t, req)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); got != "GET, HEAD, POST" {
		t.Errorf("Allow=%q want \"GET, HEAD, POST\"", got)
	}
}

func TestHandler_HEAD_Accepted(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodHead, f.endpoint, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp := f.doRequest(t, req)
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusMethodNotAllowed {
		t.Fatalf("HEAD returned 405")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 without bearer credentials", resp.StatusCode)
	}
}

// decodeBody parses the JSON response body, failing the test on errors.
func decodeBody(tb testing.TB, resp *http.Response) map[string]any {
	tb.Helper()
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		tb.Fatalf("decode body: %v", err)
	}
	return body
}

// assertNoClaimLeak fails the test if the response body contains any
// recognisable claim name (sub / email / etc.). The OIDC error paths
// must not echo claims back to the client; this defends against
// regressions that accidentally surface them through, e.g., http.Error.
func assertNoClaimLeak(tb testing.TB, resp *http.Response) {
	tb.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("read body: %v", err)
	}
	if len(raw) == 0 {
		return
	}
	for _, name := range []string{`"sub"`, `"email"`, `"name"`, `"phone_number"`, `"address"`} {
		if strings.Contains(string(raw), name) {
			tb.Fatalf("error response leaked claim %s: %s", name, raw)
		}
	}
}

// Compile-time check that op.Clock and the userinfo Clock are
// structurally compatible: a fixedClock value must satisfy both
// without an explicit converter.
var _ interface{ Now() time.Time } = fixedClock{}

// saveOpaqueAccessToken seeds the testkit's opaque-access-token
// substore with a live record. The token's raw
// [store.OpaqueAccessToken.ID] is the bearer string the test posts at
// /userinfo; the substore hashes it on Save and matches the digest on
// Find.
func (f *userInfoFixture) saveOpaqueAccessToken(tb testing.TB, rec *store.OpaqueAccessToken) {
	tb.Helper()
	if err := f.prov.Store.OpaqueAccessTokens().Save(context.Background(), rec); err != nil {
		tb.Fatalf("OpaqueAccessTokens.Save: %v", err)
	}
}

// TestHandler_OpaqueAccessToken_HappyPath confirms /userinfo accepts
// a non-JWS bearer when the opaque substore holds a live record. The
// handler hashes the presented token on lookup, projects the record's
// Subject onto a synthetic [tokens.AccessTokenClaims], and runs the
// same claim-assembly path the JWT branch uses.
func TestHandler_OpaqueAccessToken_HappyPath(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	f.putUser(t, "user-opaque", map[string]any{
		"email":          "alice@example.com",
		"email_verified": true,
	})
	rec := &store.OpaqueAccessToken{
		ID:        "opaque-userinfo-1",
		ClientID:  fixtureClientID,
		Subject:   "user-opaque",
		Scope:     []string{"openid", "email"},
		IssuedAt:  f.clock.now,
		ExpiresAt: f.clock.now.Add(time.Hour),
	}
	f.saveOpaqueAccessToken(t, rec)

	resp := f.doRequest(t, f.newGet(t, rec.ID))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, dump)
	}
	body := decodeBody(t, resp)
	if body["sub"] != "user-opaque" {
		t.Errorf("sub=%v want user-opaque", body["sub"])
	}
	if body["email"] != "alice@example.com" {
		t.Errorf("email=%v want alice@example.com", body["email"])
	}
}

// TestHandler_OpaqueAccessToken_PairwiseSubject confirms an opaque token
// preserves its grant lineage when projected onto the shared UserInfo claim
// pipeline. Pairwise projection needs that lineage to recover the raw
// OP-internal subject before querying UserStore and deriving the client-facing
// subject.
func TestHandler_OpaqueAccessToken_PairwiseSubject(t *testing.T) {
	t.Parallel()

	salt := []byte("userinfo-pairwise-opaque-salt-32b")
	f := newUserInfoFixtureWithOptions(t, op.WithPairwiseSubject(salt))
	client := f.prov.RegisterClient(t, testkit.ClientFixture{
		ID:           "client-opaque-pairwise",
		RedirectURIs: []string{"https://rp.example.test/callback"},
		SubjectType:  "pairwise",
	})
	const (
		rawSubject = "user-opaque-pairwise"
		grantID    = "grant-opaque-pairwise"
	)
	f.putUser(t, rawSubject, map[string]any{
		"email":          "pairwise@example.com",
		"email_verified": true,
	})
	if err := f.prov.Store.Grants().Save(context.Background(), &store.Grant{
		ID:        grantID,
		Subject:   rawSubject,
		ClientID:  client.ID,
		Scope:     []string{"openid", "email"},
		CreatedAt: f.clock.now,
		UpdatedAt: f.clock.now,
	}); err != nil {
		t.Fatalf("Grants.Save: %v", err)
	}
	rec := &store.OpaqueAccessToken{
		ID:        "opaque-userinfo-pairwise",
		GrantID:   grantID,
		ClientID:  client.ID,
		Subject:   rawSubject,
		Scope:     []string{"openid", "email"},
		IssuedAt:  f.clock.now,
		ExpiresAt: f.clock.now.Add(time.Hour),
	}
	f.saveOpaqueAccessToken(t, rec)

	resp := f.doRequest(t, f.newGet(t, rec.ID))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, dump)
	}

	expected, err := subject.Pairwise(salt).Generate(context.Background(), subject.GeneratorInput{
		InternalUserID: rawSubject,
		Client:         client,
	})
	if err != nil {
		t.Fatalf("Pairwise.Generate: %v", err)
	}
	body := decodeBody(t, resp)
	if got := body["sub"]; got != string(expected) {
		t.Errorf("sub=%v want pairwise subject %q", got, expected)
	}
	if got := body["email"]; got != "pairwise@example.com" {
		t.Errorf("email=%v want pairwise@example.com", got)
	}
}

// TestHandler_OpaqueAccessToken_Revoked returns 401 invalid_token
// with a "revoked" description when the substore reports the record
// as revoked.
func TestHandler_OpaqueAccessToken_Revoked(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	f.putUser(t, "user-opaque", map[string]any{"email": "alice@example.com"})
	rec := &store.OpaqueAccessToken{
		ID:        "opaque-userinfo-revoked",
		ClientID:  fixtureClientID,
		Subject:   "user-opaque",
		Scope:     []string{"openid", "email"},
		IssuedAt:  f.clock.now,
		ExpiresAt: f.clock.now.Add(time.Hour),
	}
	f.saveOpaqueAccessToken(t, rec)
	if err := f.prov.Store.OpaqueAccessTokens().RevokeByID(context.Background(), rec.ID); err != nil {
		t.Fatalf("RevokeByID: %v", err)
	}

	resp := f.doRequest(t, f.newGet(t, rec.ID))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	got := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(got, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate=%q must declare invalid_token", got)
	}
	if !strings.Contains(got, "revoked") {
		t.Errorf("WWW-Authenticate=%q must distinguish the revoked case", got)
	}
	assertNoClaimLeak(t, resp)
}

// TestHandler_OpaqueAccessToken_Expired returns 401 invalid_token
// with an "expired" description when the record's ExpiresAt is in
// the past relative to the fixture clock.
func TestHandler_OpaqueAccessToken_Expired(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	f.putUser(t, "user-opaque", map[string]any{"email": "alice@example.com"})
	rec := &store.OpaqueAccessToken{
		ID:        "opaque-userinfo-expired",
		ClientID:  fixtureClientID,
		Subject:   "user-opaque",
		Scope:     []string{"openid", "email"},
		IssuedAt:  f.clock.now.Add(-2 * time.Hour),
		ExpiresAt: f.clock.now.Add(-time.Hour),
	}
	f.saveOpaqueAccessToken(t, rec)

	resp := f.doRequest(t, f.newGet(t, rec.ID))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	got := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(got, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate=%q must declare invalid_token", got)
	}
	if !strings.Contains(got, "expired") {
		t.Errorf("WWW-Authenticate=%q must distinguish the expired case", got)
	}
	assertNoClaimLeak(t, resp)
}

// TestHandler_OpaqueAccessToken_NotFound returns 401 invalid_token
// (generic description) when the presented bearer does not match any
// stored opaque record. The challenge stays on the canonical "Bearer
// invalid_token" code so RP libraries that key off the OAuth-Bearer
// state machine continue to function.
func TestHandler_OpaqueAccessToken_NotFound(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	resp := f.doRequest(t, f.newGet(t, "never-issued-opaque"))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	got := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(got, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate=%q must declare invalid_token", got)
	}
	if strings.Contains(got, "revoked") || strings.Contains(got, "expired") {
		t.Errorf("WWW-Authenticate=%q must use the generic description for not-found", got)
	}
	assertNoClaimLeak(t, resp)
}

// TestHandler_OpaqueAccessToken_DPoPMismatch returns 401 invalid_token
// with the DPoP scheme when the record carries a DPoPJKT but the
// caller did not present a DPoP proof. The cnf-mismatch path mirrors
// the JWT branch; the difference is that the bound thumbprint comes
// from the persistent record rather than a JWT claim.
func TestHandler_OpaqueAccessToken_DPoPMismatch(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	f.putUser(t, "user-opaque", map[string]any{"email": "alice@example.com"})
	rec := &store.OpaqueAccessToken{
		ID:        "opaque-userinfo-dpop",
		ClientID:  fixtureClientID,
		Subject:   "user-opaque",
		Scope:     []string{"openid"},
		IssuedAt:  f.clock.now,
		ExpiresAt: f.clock.now.Add(time.Hour),
		DPoPJKT:   "bound-thumbprint",
	}
	f.saveOpaqueAccessToken(t, rec)

	resp := f.doRequest(t, f.newGet(t, rec.ID))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	got := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(got, "DPoP ") {
		t.Errorf("WWW-Authenticate=%q want DPoP-scheme challenge", got)
	}
	if !strings.Contains(got, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate=%q must declare invalid_token", got)
	}
	assertNoClaimLeak(t, resp)
}

// TestHandler_OpaqueAccessToken_MTLSMismatch returns 401 invalid_token
// with the Bearer scheme when the record carries a MTLSCertThumbprint
// but the caller did not present a client certificate. Mirrors the
// JWT-branch enforcement on x5t#S256.
func TestHandler_OpaqueAccessToken_MTLSMismatch(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixture(t)
	f.putUser(t, "user-opaque", map[string]any{"email": "alice@example.com"})
	rec := &store.OpaqueAccessToken{
		ID:                 "opaque-userinfo-mtls",
		ClientID:           "client-1",
		Subject:            "user-opaque",
		Scope:              []string{"openid"},
		IssuedAt:           f.clock.now,
		ExpiresAt:          f.clock.now.Add(time.Hour),
		MTLSCertThumbprint: "bound-x5t",
	}
	f.saveOpaqueAccessToken(t, rec)

	resp := f.doRequest(t, f.newGet(t, rec.ID))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}
	got := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(got, "Bearer ") {
		t.Errorf("WWW-Authenticate=%q want Bearer-scheme challenge", got)
	}
	if !strings.Contains(got, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate=%q must declare invalid_token", got)
	}
	assertNoClaimLeak(t, resp)
}
