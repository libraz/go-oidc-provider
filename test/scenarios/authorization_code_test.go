package scenarios_test

// Catalog: test/scenarios/catalog/authorization_code.yaml (AC-NNN)
// Spec:
//   - RFC 6749 §4.1 — Authorization Code Grant
//   - RFC 6749 §4.1.3 — Access Token Request
//   - RFC 6749 §5.1 / §5.2 — Token Response & Error Format
//   - OpenID Connect Core 1.0 §3.1.3 — Token Endpoint
//   - RFC 8414 / RFC 6750 — Bearer Token Usage
//   - RFC 7636 — PKCE (cross-reference for redirect_uri reuse semantics)

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// advanceableClock is a manually-advanced [op.Clock] used by AC error
// scenarios that need to push the wall clock past an authorization
// code's TTL without sleeping. It is local to this file because it is
// the only place in the scenario suite that currently needs it; if a
// second feature picks up the same pattern the helper should move to
// scenariokit.
type advanceableClock struct {
	mu  sync.Mutex
	now time.Time
}

func newAdvanceableClock(start time.Time) *advanceableClock {
	return &advanceableClock{now: start}
}

func (c *advanceableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *advanceableClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// postRefreshToken issues a refresh_token grant against the OP and
// returns the parsed envelope. It mirrors [scenariokit.ExchangeCode]
// but for the refresh path; scenariokit does not yet ship a refresh
// helper, and AC-006 is the only scenario in this file that needs one.
// If a second feature picks up the refresh path the helper should
// move to scenariokit.
func postRefreshToken(tb testing.TB, p *testkit.Provider, refreshToken, clientID, clientSecret string) scenariokit.TokenResponse {
	tb.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		p.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		tb.Fatalf("postRefreshToken: build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID != "" && clientSecret != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		tb.Fatalf("postRefreshToken: POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("postRefreshToken: read body: %v", err)
	}
	out := scenariokit.TokenResponse{StatusCode: resp.StatusCode, Raw: map[string]any{}}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &out.Raw); err != nil {
			tb.Fatalf("postRefreshToken: decode body %q: %v", string(body), err)
		}
	}
	out.AccessToken, _ = out.Raw["access_token"].(string)
	out.IDToken, _ = out.Raw["id_token"].(string)
	out.RefreshToken, _ = out.Raw["refresh_token"].(string)
	out.TokenType, _ = out.Raw["token_type"].(string)
	out.Scope, _ = out.Raw["scope"].(string)
	if expN, ok := out.Raw["expires_in"].(float64); ok {
		out.ExpiresIn = int(expN)
	}
	return out
}

func TestScenario_AC_001_MultiURISuccessReturnsTokens(t *testing.T) {
	t.Parallel()

	const (
		clientID    = "rp-ac-001"
		callback    = "https://rp.testkit.invalid/callback"
		altCallback = "https://rp.testkit.invalid/alt"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ac-001-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithStrictOfflineAccess()))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback, altCallback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	if flow.State != scenariokit.DefaultState {
		t.Errorf("state=%q want %q", flow.State, scenariokit.DefaultState)
	}

	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	if tok.AccessToken == "" {
		t.Error("access_token missing")
	}
	if tok.IDToken == "" {
		t.Error("id_token missing")
	}
	if tok.ExpiresIn <= 0 {
		t.Errorf("expires_in=%d, want > 0", tok.ExpiresIn)
	}
	if tok.TokenType == "" {
		t.Error("token_type missing")
	}
	if tok.Scope == "" {
		t.Error("scope missing")
	}
	if tok.RefreshToken != "" {
		t.Errorf("refresh_token unexpectedly present (offline_access not requested): %q", tok.RefreshToken)
	}
}

func TestScenario_AC_002_NoOfflineAccessEntitiesResolved(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-002")
}

// TestScenario_AC_003_OfflineAccessIssuesRefreshToken verifies that a
// successful authorization_code exchange that requested offline_access
// receives a refresh_token alongside access_token and id_token. The
// refresh_token MUST be a non-empty string in the JSON envelope.
//
// Spec: RFC 6749 §4.1.3 / OIDC Core §11 (offline_access semantics).
func TestScenario_AC_003_OfflineAccessIssuesRefreshToken(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-ac-003"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ac-003-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithStrictOfflineAccess()))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid offline_access",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	if tok.AccessToken == "" {
		t.Error("access_token missing")
	}
	if tok.IDToken == "" {
		t.Error("id_token missing")
	}
	if tok.RefreshToken == "" {
		t.Error("refresh_token missing on offline_access exchange")
	}
}

// TestScenario_AC_004_TokenResponseIsNoStore verifies that a successful
// /token response carries Cache-Control: no-store so intermediaries do
// not cache the bearer credentials. RFC 6749 §5.1 makes this MUST.
//
// Spec: RFC 6749 §5.1 (Successful Response).
func TestScenario_AC_004_TokenResponseIsNoStore(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-ac-004"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ac-004-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {flow.Code},
		"redirect_uri":  {callback},
		"code_verifier": {pkce.Verifier},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, string(body))
	}
	cc := resp.Header.Get("Cache-Control")
	if !strings.Contains(strings.ToLower(cc), "no-store") {
		t.Errorf("Cache-Control=%q must include no-store (RFC 6749 §5.1)", cc)
	}
}

// TestScenario_AC_005_ExpiredCodeRejected checks that an authorization
// code presented after its TTL has elapsed is rejected by the token
// endpoint with HTTP 400 invalid_grant, and that no token.issued
// audit event is emitted for the failed exchange.
//
// Spec: RFC 6749 §4.1.2 (authorization code expiry) / §5.2 (error
// response shape).
func TestScenario_AC_005_ExpiredCodeRejected(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-ac-005"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ac-005-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	clock := newAdvanceableClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	audit := scenariokit.NewAuditCapture()
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithAuditLogger(audit.Logger())),
	)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	// RFC 6749 §4.1.2 mandates a "short" code lifetime; the project
	// default is 60 seconds. Push the clock well past it so the
	// exchanger sees the record as expired.
	clock.Advance(2 * time.Minute)

	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusBadRequest {
		t.Fatalf("/token status=%d body=%v, want 400", tok.StatusCode, tok.Raw)
	}
	gotErr, _ := tok.Raw["error"].(string)
	if gotErr != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant", gotErr)
	}
	if desc, _ := tok.Raw["error_description"].(string); desc == "" {
		t.Error("error_description missing on expired-code response")
	}
	if tok.AccessToken != "" || tok.IDToken != "" || tok.RefreshToken != "" {
		t.Errorf("expired exchange must not mint tokens: %+v", tok.Raw)
	}
	if got := audit.EventsByName(string(op.AuditTokenIssued)); len(got) != 0 {
		t.Errorf("token.issued audit event must not fire on expired-code path: %+v", got)
	}
}

// TestScenario_AC_006_ReplayedCodeRevokesGrant checks that replaying an
// already-consumed authorization code is rejected with 400
// invalid_grant AND that the grant chain is revoked: the refresh
// token minted by the first exchange MUST no longer be redeemable.
//
// Spec: RFC 6749 §4.1.2 (codes are single-use; replay MUST trigger
// revocation of every token previously issued from the same code) /
// §10.5 (security considerations) / OIDC Core 1.0 §3.1.3.2.
func TestScenario_AC_006_ReplayedCodeRevokesGrant(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-ac-006"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ac-006-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid offline_access",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	first := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first /token status=%d body=%v", first.StatusCode, first.Raw)
	}
	if first.RefreshToken == "" {
		t.Fatal("first exchange did not mint a refresh_token")
	}

	replay := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay /token status=%d body=%v, want 400", replay.StatusCode, replay.Raw)
	}
	if got, _ := replay.Raw["error"].(string); got != "invalid_grant" {
		t.Errorf("replay error=%q want invalid_grant", got)
	}

	// The cascade MUST invalidate every token descended from the
	// replayed grant. Use the refresh_token issued by the first (valid)
	// exchange to confirm: a follow-up refresh request MUST fail with
	// invalid_grant.
	refresh := postRefreshToken(t, tk, first.RefreshToken, rp.ID, clientSecret)
	if refresh.StatusCode != http.StatusBadRequest {
		t.Fatalf("post-replay refresh /token status=%d body=%v, want 400", refresh.StatusCode, refresh.Raw)
	}
	if got, _ := refresh.Raw["error"].(string); got != "invalid_grant" {
		t.Errorf("post-replay refresh error=%q want invalid_grant", got)
	}
	if refresh.AccessToken != "" || refresh.RefreshToken != "" {
		t.Errorf("revoked refresh_token must not mint tokens: %+v", refresh.Raw)
	}
}

// TestScenario_AC_007_FirstExchangeMarksCodeConsumed verifies that the
// first valid /token exchange marks the authorization code as
// consumed: a second presentation of the same code is then rejected
// with 400 invalid_grant. The wire-observable signal of "marked
// consumed at an epoch no later than now" is the replay rejection on
// the immediately-following request.
//
// Spec: RFC 6749 §4.1.2 (codes MUST be single-use) / §10.5 (replay
// guard).
func TestScenario_AC_007_FirstExchangeMarksCodeConsumed(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-ac-007"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ac-007-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	first := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first /token status=%d body=%v, want 200", first.StatusCode, first.Raw)
	}
	if first.AccessToken == "" {
		t.Fatal("first exchange did not mint an access_token")
	}

	replay := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if replay.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay /token status=%d body=%v, want 400", replay.StatusCode, replay.Raw)
	}
	if got, _ := replay.Raw["error"].(string); got != "invalid_grant" {
		t.Errorf("replay error=%q want invalid_grant", got)
	}
	if replay.AccessToken != "" || replay.IDToken != "" || replay.RefreshToken != "" {
		t.Errorf("replay must not mint tokens: %+v", replay.Raw)
	}
}

// TestScenario_AC_008_ClientMismatchRejected verifies that a client
// other than the one that requested the authorization code cannot
// redeem it. The token endpoint MUST reject the exchange with
// invalid_grant and MUST NOT mint tokens.
//
// Spec: RFC 6749 §4.1.3 (authenticated client must match the code's
// originating client) / §10.5 (replay / cross-client guards).
func TestScenario_AC_008_ClientMismatchRejected(t *testing.T) {
	t.Parallel()

	const (
		ownerClientID  = "rp-ac-008-owner"
		callerClientID = "rp-ac-008-caller"
		callback       = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const ownerSecret = "rp-ac-008-owner-secret"
	//nolint:gosec // test fixture: not a real credential.
	const callerSecret = "rp-ac-008-caller-secret"

	ownerHash, err := op.HashClientSecret(ownerSecret)
	if err != nil {
		t.Fatalf("HashClientSecret(owner): %v", err)
	}
	callerHash, err := op.HashClientSecret(callerSecret)
	if err != nil {
		t.Fatalf("HashClientSecret(caller): %v", err)
	}

	audit := scenariokit.NewAuditCapture()
	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithAuditLogger(audit.Logger())))

	owner := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      ownerClientID,
		SecretHash:              ownerHash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      callerClientID,
		SecretHash:              callerHash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    owner.ID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     callerClientID,
		ClientSecret: callerSecret,
	})
	if tok.StatusCode != http.StatusBadRequest {
		t.Fatalf("/token status=%d body=%v, want 400", tok.StatusCode, tok.Raw)
	}
	if got, _ := tok.Raw["error"].(string); got != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant", got)
	}
	if tok.AccessToken != "" || tok.IDToken != "" || tok.RefreshToken != "" {
		t.Errorf("cross-client exchange must not mint tokens: %+v", tok.Raw)
	}
	if got := audit.EventsByName(string(op.AuditTokenIssued)); len(got) != 0 {
		t.Errorf("token.issued audit event must not fire on client-mismatch path: %+v", got)
	}
}

// TestScenario_AC_009_UnsupportedGrantTypeRejected verifies that a
// /token request whose grant_type is neither "authorization_code",
// "refresh_token", nor any of the OP's enabled grants yields 400
// unsupported_grant_type. The dispatcher MUST reject the value before
// any side effect, so no audit events about token issuance fire.
//
// Spec: RFC 6749 §5.2 ("The authorization grant type is not supported
// by the authorization server").
func TestScenario_AC_009_UnsupportedGrantTypeRejected(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-ac-009"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ac-009-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	form := url.Values{
		"grant_type": {"urn:example:made-up-grant"},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if got, _ := env["error"].(string); got != "unsupported_grant_type" {
		t.Errorf("error=%q want unsupported_grant_type (raw=%s)", got, string(body))
	}
}

// TestScenario_AC_010_RedirectURIMismatchRejected checks that the
// redirect_uri presented on the token request must match the value
// recorded at /authorize. Submitting a registered-but-different URI
// MUST yield 400 invalid_grant and MUST NOT mint tokens.
//
// Spec: RFC 6749 §4.1.3 (the redirect_uri parameter MUST exact-match
// the authorize-time value when included in the request).
func TestScenario_AC_010_RedirectURIMismatchRejected(t *testing.T) {
	t.Parallel()

	const (
		clientID    = "rp-ac-010"
		callback    = "https://rp.testkit.invalid/callback"
		altCallback = "https://rp.testkit.invalid/alt"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ac-010-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	audit := scenariokit.NewAuditCapture()
	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithAuditLogger(audit.Logger())))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback, altCallback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code: flow.Code,
		// altCallback is registered, so the request is structurally
		// valid; the violation is that it does not match the value
		// the OP captured at /authorize for this code.
		RedirectURI:  altCallback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusBadRequest {
		t.Fatalf("/token status=%d body=%v, want 400", tok.StatusCode, tok.Raw)
	}
	if got, _ := tok.Raw["error"].(string); got != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant", got)
	}
	if tok.AccessToken != "" || tok.IDToken != "" || tok.RefreshToken != "" {
		t.Errorf("redirect_uri-mismatch exchange must not mint tokens: %+v", tok.Raw)
	}
	if got := audit.EventsByName(string(op.AuditTokenIssued)); len(got) != 0 {
		t.Errorf("token.issued audit event must not fire on redirect_uri-mismatch path: %+v", got)
	}
}

// TestScenario_AC_011_MultiURIClientMustSendRedirectURI verifies the
// canonical "<param> is required" wire phrasing of RFC 6749 §4.1.3:
// a multi-URI client that omits `redirect_uri` at /token receives 400
// invalid_request whose error_description names the parameter and
// uses the "is required" form. AC-027 covers the looser
// "must include redirect_uri somewhere" contract; this row pins the
// phrase shape so the wire wording does not silently drift.
//
// Spec: RFC 6749 §4.1.3 / §5.2.
func TestScenario_AC_011_MultiURIClientMustSendRedirectURI(t *testing.T) {
	t.Parallel()

	const (
		clientID    = "rp-ac-011"
		callback    = "https://rp.testkit.invalid/callback"
		altCallback = "https://rp.testkit.invalid/alt"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ac-011-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback, altCallback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {flow.Code},
		"code_verifier": {pkce.Verifier},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if got, _ := env["error"].(string); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (raw=%s)", got, string(body))
	}
	desc, _ := env["error_description"].(string)
	if !strings.Contains(desc, "redirect_uri") {
		t.Errorf("error_description=%q must name redirect_uri", desc)
	}
	if !strings.Contains(desc, "is required") {
		t.Errorf("error_description=%q must use canonical \"is required\" phrasing", desc)
	}
}

func TestScenario_AC_012_AccountNotFoundRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-012")
}

func TestScenario_AC_013_SingleURIWithoutAllowOmitRequiresParam(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-013")
}

func TestScenario_AC_014_SingleURIAllowOmitSuccess(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-014")
}

func TestScenario_AC_015_SingleURIAllowOmitNoOfflineEntities(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-015")
}

func TestScenario_AC_016_SingleURIAllowOmitOfflineEntities(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-016")
}

func TestScenario_AC_017_SingleURIAllowOmitNoStore(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-017")
}

func TestScenario_AC_018_SingleURIAllowOmitExpiredCode(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-018")
}

func TestScenario_AC_019_SingleURIAllowOmitReplayedCode(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-019")
}

func TestScenario_AC_020_SingleURIAllowOmitMarksConsumed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-020")
}

func TestScenario_AC_021_SingleURIAllowOmitClientMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-021")
}

func TestScenario_AC_022_SingleURIAllowOmitUnsupportedGrant(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-022")
}

func TestScenario_AC_023_SingleURIAllowOmitRedirectURIMismatch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-023")
}

func TestScenario_AC_024_SingleURIAllowOmitAccountNotFound(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-024")
}

// TestScenario_AC_025_EmptyBodyMissingGrantType verifies that a
// /token POST with no parameters at all is rejected with 400
// invalid_request and an error_description that names `grant_type`.
// The dispatcher MUST stop before any grant-specific handler.
//
// Spec: RFC 6749 §5.2 (invalid_request when "the request is missing a
// required parameter").
func TestScenario_AC_025_EmptyBodyMissingGrantType(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(""))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if got, _ := env["error"].(string); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (raw=%s)", got, string(body))
	}
	if desc, _ := env["error_description"].(string); !strings.Contains(desc, "grant_type") {
		t.Errorf("error_description=%q must mention grant_type", desc)
	}
}

// TestScenario_AC_026_AuthCodeWithoutCodeParam verifies that a /token
// request with grant_type=authorization_code but no `code` parameter
// is rejected with 400 invalid_request and an error_description that
// names `code`.
//
// Spec: RFC 6749 §4.1.3 / §5.2.
func TestScenario_AC_026_AuthCodeWithoutCodeParam(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-ac-026"
		callback = "https://rp.testkit.invalid/callback"
	)
	const clientSecret = "rp-ac-026-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	form := url.Values{
		"grant_type":   {"authorization_code"},
		"redirect_uri": {callback},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if got, _ := env["error"].(string); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (raw=%s)", got, string(body))
	}
	if desc, _ := env["error_description"].(string); !strings.Contains(desc, "code") {
		t.Errorf("error_description=%q must mention code", desc)
	}
}

// TestScenario_AC_027_MultiURIWithoutRedirectURIParam verifies that a
// /token request from a client with multiple registered redirect_uris
// must include `redirect_uri`. Omitting it yields 400 invalid_request
// with an error_description that names `redirect_uri`.
//
// Spec: RFC 6749 §4.1.3 (the redirect_uri MUST be included when the
// /authorize request used it; multi-URI clients have no canonical
// fallback, so the wire form is required).
func TestScenario_AC_027_MultiURIWithoutRedirectURIParam(t *testing.T) {
	t.Parallel()

	const (
		clientID    = "rp-ac-027"
		callback    = "https://rp.testkit.invalid/callback"
		altCallback = "https://rp.testkit.invalid/alt"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ac-027-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback, altCallback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	// Deliberately omit redirect_uri at /token.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {flow.Code},
		"code_verifier": {pkce.Verifier},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if got, _ := env["error"].(string); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (raw=%s)", got, string(body))
	}
	if desc, _ := env["error_description"].(string); !strings.Contains(desc, "redirect_uri") {
		t.Errorf("error_description=%q must mention redirect_uri", desc)
	}
}

// TestScenario_AC_028_UnknownCodeRejected checks that a well-formed
// but non-existent authorization code value is rejected with 400
// invalid_grant. The OP MUST NOT mint tokens for an unknown code.
//
// Spec: RFC 6749 §5.2 — invalid_grant covers "the provided
// authorization grant ... is invalid, expired, revoked, ..."; an
// unknown code is one of these failure modes.
func TestScenario_AC_028_UnknownCodeRejected(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-ac-028"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ac-028-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	// 43 chars is well above the OP's accepted "code" length and uses
	// only the unreserved alphabet — structurally well-formed, but no
	// such record exists in the store.
	const fakeCode = "scenarios-ac028-unknown-code-aaaaaaaaaaaaaa"

	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         fakeCode,
		RedirectURI:  callback,
		Verifier:     scenariokit.DefaultPKCEVerifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusBadRequest {
		t.Fatalf("/token status=%d body=%v, want 400", tok.StatusCode, tok.Raw)
	}
	if got, _ := tok.Raw["error"].(string); got != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant", got)
	}
	if tok.AccessToken != "" || tok.IDToken != "" || tok.RefreshToken != "" {
		t.Errorf("unknown-code request must not mint tokens: %+v", tok.Raw)
	}
}

func TestScenario_AC_029_DownstreamExceptionReturnsServerError(t *testing.T) {
	t.Parallel()
	t.Skip("pending: AC-029")
}
