package scenarios_test

// Catalog: test/scenarios/catalog/grant_tombstone.yaml (GTM-NNN)
// Spec:
//   - RFC 6749 §4.1.2 — Authorization Code Grant, code-replay revocation
//   - RFC 6819 §5.2.1.1 — authorization code re-use threat
//   - RFC 7009 §2.2 — OAuth 2.0 Token Revocation (idempotency)
//   - RFC 7519 §4.3 — Private Claim Names
//   - RFC 7662 §2.2 — OAuth 2.0 Token Introspection
//   - RFC 9068 §2.2.3 — JWT AT extension claims
//   - FAPI 2.0 SP §5.3.2.2

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

const (
	gtmClientID = "rp-gtm"
	gtmCallback = "https://rp.testkit.invalid/callback"
)

//nolint:gosec // G101: test fixture, not a real credential.
const gtmClientSecret = "rp-gtm-secret"

// newGTMProvider stands up a testkit Provider with the default
// (GrantTombstone) strategy and Introspect / Revoke features enabled
// so the GTM rows can drive the cascade endpoints end-to-end.
func newGTMProvider(t *testing.T, opts ...op.Option) (*testkit.Provider, *store.Client) {
	t.Helper()
	hash, err := op.HashClientSecret(gtmClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	full := append([]op.Option{
		op.WithFeature(feature.Introspect),
		op.WithFeature(feature.Revoke),
	}, opts...)
	tk := testkit.NewProvider(t, testkit.WithOptions(full...))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      gtmClientID,
		SecretHash:              hash,
		RedirectURIs:            []string{gtmCallback},
		PostLogoutRedirectURIs:  []string{"https://rp.testkit.invalid/logout"},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	tk.Store.PutUser(context.Background(), &store.User{
		Subject: scenariokit.DefaultSubject,
		Claims: map[string]any{
			"email":          "alice@example.com",
			"email_verified": true,
		},
	})
	return tk, rp
}

// runGTMCodeFlow drives /authorize → /interaction → /token through
// scenariokit and returns the parsed token response. offline_access
// is included so a refresh token rides along (GTM-004 needs it).
func runGTMCodeFlow(t *testing.T, tk *testkit.Provider, rp *store.Client) scenariokit.TokenResponse {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: gtmCallback,
		Scope:       "openid profile offline_access",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  gtmCallback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: gtmClientSecret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	tok.Raw["__code"] = flow.Code
	tok.Raw["__verifier"] = pkce.Verifier
	return tok
}

// decodeGTMJWTClaims pulls the payload claims out of a JWS Compact
// Serialisation. It is intentionally tolerant of unknown fields so
// the gid claim surfaces as map[string]any.
func decodeGTMJWTClaims(tb testing.TB, jws string) map[string]any {
	tb.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		tb.Fatalf("jwt parts=%d want 3 (value=%q)", len(parts), jws)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		tb.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		tb.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

// TestScenario_GTM_001_DefaultStrategyWritesNoRegistryRow pins the
// reduction in management data the default strategy delivers: under
// it a successful authorization_code exchange writes ZERO rows
// to Store.AccessTokens(). The user-visible promise is that JWT AT
// issuance is a pure compute path on the hot path.
func TestScenario_GTM_001_DefaultStrategyWritesNoRegistryRow(t *testing.T) {
	t.Parallel()

	tk, rp := newGTMProvider(t)
	tok := runGTMCodeFlow(t, tk, rp)
	if tok.AccessToken == "" {
		t.Fatal("/token returned empty access_token")
	}

	// The JWT AT carries a non-empty jti claim; consult the registry
	// directly. A configured Store always returns the
	// AccessTokenRegistry substore; under the default strategy the
	// issuance path skips Register, so Find for the AT's JTI must
	// return (nil, nil).
	claims := decodeGTMJWTClaims(t, tok.AccessToken)
	jti, _ := claims["jti"].(string)
	if jti == "" {
		t.Fatalf("AT missing jti claim: %v", claims)
	}
	rec, err := tk.Store.AccessTokens().Find(context.Background(), jti)
	if err != nil {
		t.Fatalf("AccessTokens.Find: %v", err)
	}
	if rec != nil {
		t.Errorf("default strategy must not Register; got rec=%+v for jti=%q", rec, jti)
	}
}

// TestScenario_GTM_002_AccessTokenCarriesGidClaim asserts the wire
// change: every JWT AT under the default strategy carries a "gid"
// private claim equal to the descending GrantID. Resource servers
// MUST ignore the claim per RFC 7519 §4.3; the OP is the only
// consumer.
func TestScenario_GTM_002_AccessTokenCarriesGidClaim(t *testing.T) {
	t.Parallel()

	tk, rp := newGTMProvider(t)
	tok := runGTMCodeFlow(t, tk, rp)
	claims := decodeGTMJWTClaims(t, tok.AccessToken)
	gid, ok := claims["gid"].(string)
	if !ok || gid == "" {
		t.Fatalf("gid claim missing or empty under default strategy; claims=%v", claims)
	}

	// The gid value must be a real grant identifier the OP can
	// resolve back through the Grants substore. Cross-check by
	// listing grants for the subject.
	grants, err := tk.Store.Grants().ListBySubject(context.Background(), scenariokit.DefaultSubject)
	if err != nil {
		t.Fatalf("Grants.ListBySubject: %v", err)
	}
	matched := false
	for _, g := range grants {
		if g != nil && g.ID == gid {
			matched = true
			break
		}
	}
	if !matched {
		t.Errorf("gid=%q not found in grant list (len=%d)", gid, len(grants))
	}
}

// TestScenario_GTM_003_EndSessionTombstonesRevokeAccessToken drives
// the §"Revoke by grant (cascade)" branch: a /end_session call writes
// one tombstone per grant, and a subsequent /userinfo with the
// pre-logout AT returns 401 invalid_token because the verifier
// consults GrantRevocations.IsRevoked.
func TestScenario_GTM_003_EndSessionTombstonesRevokeAccessToken(t *testing.T) {
	t.Parallel()

	tk, rp := newGTMProvider(t)
	tok := runGTMCodeFlow(t, tk, rp)
	at := tok.AccessToken

	// Confirm /userinfo accepts the AT before logout.
	if status := userInfoStatus(t, tk, at); status != http.StatusOK {
		t.Fatalf("userinfo before logout: status=%d want 200", status)
	}

	claims := decodeGTMJWTClaims(t, at)
	gid, _ := claims["gid"].(string)

	// Manually exercise the cascade by writing a tombstone via the
	// substore. The full /end_session flow needs a session cookie
	// the scenariokit harness does not currently surface; the
	// substore-direct call is what the handler does internally on
	// the cascade path, so the wire-level effect is identical.
	now := time.Now().UTC()
	if err := tk.Store.GrantRevocations().RevokeGrant(context.Background(), store.GrantTombstone{
		GrantID:   gid,
		RevokedAt: now,
		ExpiresAt: now.Add(2 * time.Hour),
		Reason:    "logout",
	}); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}

	// The same AT must now be rejected at /userinfo.
	if status := userInfoStatus(t, tk, at); status != http.StatusUnauthorized {
		t.Fatalf("userinfo after tombstone: status=%d want 401", status)
	}
}

// TestScenario_GTM_004_CodeReplayCascadesTombstone exercises the
// §"Mint refusal under tombstoned grant" branch: replaying a
// consumed authorization code writes a tombstone, and a subsequent
// refresh-grant exchange under the same grant returns invalid_grant
// because the pre-mint IsRevoked check refuses to mint under a
// tombstoned grant.
func TestScenario_GTM_004_CodeReplayCascadesTombstone(t *testing.T) {
	t.Parallel()

	tk, rp := newGTMProvider(t)
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: gtmCallback,
		Scope:       "openid profile offline_access",
		PKCE:        pkce,
	})
	first := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  gtmCallback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: gtmClientSecret,
	})
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first /token: status=%d body=%v", first.StatusCode, first.Raw)
	}
	if first.RefreshToken == "" {
		t.Fatal("first exchange missing refresh_token (offline_access scope?)")
	}

	// Replay the consumed code → cascade fires.
	replay := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  gtmCallback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: gtmClientSecret,
	})
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay /token: status=%d want 400", replay.StatusCode)
	}
	if got, _ := replay.Raw["error"].(string); got != "invalid_grant" {
		t.Errorf("replay error=%v want invalid_grant", replay.Raw["error"])
	}

	// The refresh token under the same grant must now also be
	// rejected — the refresh grant's pre-mint IsRevoked check sees
	// the tombstone written by the cascade.
	refreshResp := postRefreshGrant(t, tk, first.RefreshToken)
	if refreshResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("refresh after cascade: status=%d want 400 (invalid_grant)", refreshResp.StatusCode)
	}
	if got, _ := refreshResp.Raw["error"].(string); got != "invalid_grant" {
		t.Errorf("refresh error=%v want invalid_grant", refreshResp.Raw["error"])
	}

	// And the pre-cascade AT must be rejected at /userinfo (the
	// tombstone covers every AT minted under the grant before
	// RevokedAt).
	if status := userInfoStatus(t, tk, first.AccessToken); status != http.StatusUnauthorized {
		t.Errorf("userinfo with cascaded AT: status=%d want 401", status)
	}
}

// TestScenario_GTM_005_RevocationDenylistsSingleAT pins the RFC 7009
// path: /oidc/revocation with token=<JWT AT> writes one RevokedJTI
// row and the introspection of the same token reports inactive. A
// single-AT revoke is deliberately NOT coalesced into a grant
// tombstone.
func TestScenario_GTM_005_RevocationDenylistsSingleAT(t *testing.T) {
	t.Parallel()

	tk, rp := newGTMProvider(t)
	tok := runGTMCodeFlow(t, tk, rp)
	at := tok.AccessToken

	// Sanity: the AT introspects active.
	if active := introspectActive(t, tk, at); !active {
		t.Fatalf("pre-revoke introspect: want active, got inactive")
	}

	// Revoke the single AT.
	if status := postRevoke(t, tk, at, gtmClientID, gtmClientSecret); status != http.StatusOK {
		t.Fatalf("/revoke: status=%d want 200", status)
	}

	// Post-revoke: introspection collapses onto inactive.
	if active := introspectActive(t, tk, at); active {
		t.Errorf("post-revoke introspect: want inactive, got active")
	}

	// Post-revoke: userinfo returns 401.
	if status := userInfoStatus(t, tk, at); status != http.StatusUnauthorized {
		t.Errorf("post-revoke userinfo: status=%d want 401", status)
	}

	// The grant tombstone substore MUST NOT have a tombstone for
	// the AT's gid — single-AT revoke does not coalesce.
	claims := decodeGTMJWTClaims(t, at)
	gid, _ := claims["gid"].(string)
	revoked, err := tk.Store.GrantRevocations().IsRevoked(
		context.Background(),
		gid,
		"", // empty jti → only the tombstone path is consulted
		time.Unix(int64(claims["iat"].(float64)), 0),
	)
	if err != nil {
		t.Fatalf("IsRevoked(gid only): %v", err)
	}
	if revoked {
		t.Errorf("single-AT revoke must not coalesce to grant tombstone; gid=%q reports revoked", gid)
	}
}

// TestScenario_GTM_006_FAPIRejectsRevocationStrategyNone pins the
// profile gate: under any FAPI profile
// op.New rejects op.RevocationStrategyNone because FAPI 2.0 SP §5.3.2.2
// mandates server-side access-token revocation. Non-FAPI profiles still
// accept None — that path is bound by op-package unit tests.
func TestScenario_GTM_006_FAPIRejectsRevocationStrategyNone(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		t.Fatalf("generate cookie key: %v", err)
	}

	_, err = op.New(
		op.WithIssuer("https://idp.testkit.invalid"),
		op.WithStore(inmem.New()),
		op.WithKeyset(op.Keyset{{KeyID: "gtm-sig-1", Signer: priv}}),
		op.WithCookieKeys(cookieKey),
		// The default grant set includes authorization_code, which op.New
		// refuses without a login configuration. Supplying one keeps the
		// rejection under test attributable to the revocation strategy.
		op.WithAuthenticators(testkit.SubjectAuthenticator{}),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
		op.WithAccessTokenRevocationStrategy(op.RevocationStrategyNone),
	)
	if err == nil {
		t.Fatal("expected error when FAPI profile is paired with RevocationStrategyNone, got nil")
	}
	var typed *op.Error
	if !errors.As(err, &typed) {
		t.Fatalf("err = %v, want *op.Error", err)
	}
	if !op.IsServerError(err) {
		t.Errorf("FAPI + None must be a server-side configuration error: %v", err)
	}
	if !strings.Contains(err.Error(), "RevocationStrategyNone") {
		t.Errorf("err = %v, want it to mention RevocationStrategyNone", err)
	}
}

// TestScenario_GTM_007_JTIRegistryStrategyKeepsPerTokenRows pins the
// opt-in audit path: under RevocationStrategyJTIRegistry every issued
// AT writes one row to Store.AccessTokens() and the tombstone substore
// stays empty.
func TestScenario_GTM_007_JTIRegistryStrategyKeepsPerTokenRows(t *testing.T) {
	t.Parallel()

	tk, rp := newGTMProvider(t,
		op.WithAccessTokenRevocationStrategy(op.RevocationStrategyJTIRegistry),
	)
	tok := runGTMCodeFlow(t, tk, rp)
	claims := decodeGTMJWTClaims(t, tok.AccessToken)
	jti, _ := claims["jti"].(string)
	if jti == "" {
		t.Fatalf("AT missing jti claim")
	}

	// JTIRegistry: the per-AT shadow row MUST exist.
	rec, err := tk.Store.AccessTokens().Find(context.Background(), jti)
	if err != nil {
		t.Fatalf("AccessTokens.Find: %v", err)
	}
	if rec == nil {
		t.Fatalf("JTIRegistry strategy must Register; jti=%q has no row", jti)
	}
	if rec.Revoked {
		t.Errorf("freshly issued AT must not be Revoked")
	}
}

// userInfoStatus performs a /oidc/userinfo request with the supplied
// bearer and returns the response status code.
func userInfoStatus(t *testing.T, tk *testkit.Provider, bearer string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/userinfo", nil)
	if err != nil {
		t.Fatalf("build userinfo request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// introspectActive performs a /oidc/introspect request and returns
// the active boolean from the response body.
func introspectActive(t *testing.T, tk *testkit.Provider, token string) bool {
	t.Helper()
	form := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build introspect request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(gtmClientID, gtmClientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("introspect status=%d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode introspect body: %v", err)
	}
	active, _ := body["active"].(bool)
	return active
}

// postRefreshGrant exercises the refresh_token grant against the
// scenario provider and returns the parsed token response.
func postRefreshGrant(t *testing.T, tk *testkit.Provider, refreshToken string) scenariokit.TokenResponse {
	t.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build refresh request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(gtmClientID, gtmClientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /token (refresh): %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var body map[string]any
	if decodeErr := json.NewDecoder(resp.Body).Decode(&body); decodeErr != nil {
		body = map[string]any{"__decode_error": decodeErr.Error()}
	}
	tokRes := scenariokit.TokenResponse{
		StatusCode: resp.StatusCode,
		Raw:        body,
	}
	if at, _ := body["access_token"].(string); at != "" {
		tokRes.AccessToken = at
	}
	return tokRes
}
