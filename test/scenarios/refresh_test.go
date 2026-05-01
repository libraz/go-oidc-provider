package scenarios_test

// Catalog: test/scenarios/catalog/refresh.yaml (REF-NNN)
// Spec:
//   - RFC 6749 §6 — Refreshing an Access Token
//   - RFC 6749 §5.1 / §5.2 — Successful and Error Response
//   - RFC 6749 §10.4 — Refresh Token Security
//   - OIDC Core 1.0 §11 — Offline Access
//   - OIDC Core 1.0 §12 — Using Refresh Tokens
//   - RFC 9700 §4.13 — Refresh Token Replay
//   - RFC 9700 §4.14 — Refresh Token Rotation

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// TestScenario_REF_001_NonRotatingRefreshSuccess verifies the
// vanilla refresh_token grant: a refresh_token redeemed by its owning
// client returns 200 with access_token, id_token, expires_in,
// token_type, refresh_token, and scope. The testkit defaults to a
// non-rotating refresh policy so the response carries a refresh_token
// without needing per-test rotation toggles. This row pins the
// successful wire envelope shape; nonce preservation and audit
// emission are covered by other rows (REF-002, REF-013).
//
// Spec: RFC 6749 §6 / §5.1, OIDC Core §12.
func TestScenario_REF_001_NonRotatingRefreshSuccess(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-ref-001"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ref-001-secret"

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
		t.Fatal("first exchange missing refresh_token (offline_access scope?)")
	}

	refreshed := postRefreshToken(t, tk, first.RefreshToken, rp.ID, clientSecret)
	if refreshed.StatusCode != http.StatusOK {
		t.Fatalf("/token refresh status=%d body=%v, want 200", refreshed.StatusCode, refreshed.Raw)
	}
	if refreshed.AccessToken == "" {
		t.Error("refresh response missing access_token")
	}
	if refreshed.IDToken == "" {
		t.Error("refresh response missing id_token")
	}
	if refreshed.RefreshToken == "" {
		t.Error("refresh response missing refresh_token (non-rotating policy must carry one)")
	}
	if refreshed.TokenType == "" {
		t.Error("refresh response missing token_type")
	}
	if refreshed.ExpiresIn <= 0 {
		t.Errorf("refresh response expires_in=%d, want > 0", refreshed.ExpiresIn)
	}
	if refreshed.Scope == "" {
		t.Error("refresh response missing scope")
	}
}

func TestScenario_REF_002_NonRotatingRefreshEntities(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-002")
}

// TestScenario_REF_003_ExpiredRefreshTokenRejected verifies that a
// refresh_token presented after its TTL is rejected with 400
// invalid_grant. The wall clock is advanced past WithRefreshTokenTTL
// using a manually-driven [op.Clock] so the test does not sleep.
//
// Spec: RFC 6749 §6 / §10.4.
func TestScenario_REF_003_ExpiredRefreshTokenRejected(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-ref-003"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ref-003-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	clock := newAdvanceableClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithStrictOfflineAccess(),
			op.WithRefreshTokenTTL(2*time.Minute),
		),
	)
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
	if first.StatusCode != http.StatusOK || first.RefreshToken == "" {
		t.Fatalf("first /token must return refresh_token: status=%d body=%v", first.StatusCode, first.Raw)
	}

	clock.Advance(10 * time.Minute)

	expired := postRefreshToken(t, tk, first.RefreshToken, rp.ID, clientSecret)
	if expired.StatusCode != http.StatusBadRequest {
		t.Fatalf("expired-refresh status=%d body=%v, want 400", expired.StatusCode, expired.Raw)
	}
	if got, _ := expired.Raw["error"].(string); got != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant (raw=%v)", got, expired.Raw)
	}
	if expired.AccessToken != "" || expired.RefreshToken != "" {
		t.Errorf("expired refresh must not mint tokens: %+v", expired.Raw)
	}
}

// TestScenario_REF_004_RefreshClientMismatchRejected verifies that a
// refresh_token presented by a different (registered) client is
// rejected with 400 invalid_grant. The OP MUST tie the redemption to
// the client that originally received the token.
//
// Spec: RFC 6749 §6 / §10.4.
func TestScenario_REF_004_RefreshClientMismatchRejected(t *testing.T) {
	t.Parallel()

	const (
		ownerClientID    = "rp-ref-004-owner"
		strangerClientID = "rp-ref-004-stranger"
		callback         = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const ownerSecret = "rp-ref-004-owner-secret"
	//nolint:gosec // test fixture: not a real credential.
	const strangerSecret = "rp-ref-004-stranger-secret"

	ownerHash, err := op.HashClientSecret(ownerSecret)
	if err != nil {
		t.Fatalf("HashClientSecret(owner): %v", err)
	}
	strangerHash, err := op.HashClientSecret(strangerSecret)
	if err != nil {
		t.Fatalf("HashClientSecret(stranger): %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithStrictOfflineAccess()))
	owner := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      ownerClientID,
		SecretHash:              ownerHash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})
	stranger := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      strangerClientID,
		SecretHash:              strangerHash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    owner.ID,
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
		ClientID:     owner.ID,
		ClientSecret: ownerSecret,
	})
	if first.StatusCode != http.StatusOK || first.RefreshToken == "" {
		t.Fatalf("owner /token must return refresh_token: status=%d body=%v", first.StatusCode, first.Raw)
	}

	mismatched := postRefreshToken(t, tk, first.RefreshToken, stranger.ID, strangerSecret)
	if mismatched.StatusCode != http.StatusBadRequest {
		t.Fatalf("client-mismatch status=%d body=%v, want 400", mismatched.StatusCode, mismatched.Raw)
	}
	if got, _ := mismatched.Raw["error"].(string); got != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant (raw=%v)", got, mismatched.Raw)
	}
	if mismatched.AccessToken != "" || mismatched.RefreshToken != "" {
		t.Errorf("client-mismatch must not mint tokens: %+v", mismatched.Raw)
	}
}

// TestScenario_REF_005_ScopeUpgradeSingleRejected verifies that a
// refresh_token request whose `scope` parameter contains a single
// scope not in the original grant is rejected with 400 invalid_scope.
// The OP MUST NOT widen the access bestowed by the original consent.
//
// Spec: RFC 6749 §6 (scope MUST NOT exceed the original).
func TestScenario_REF_005_ScopeUpgradeSingleRejected(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-ref-005"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ref-005-secret"

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
	first := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if first.StatusCode != http.StatusOK || first.RefreshToken == "" {
		t.Fatalf("first /token must return refresh_token: status=%d body=%v", first.StatusCode, first.Raw)
	}

	// Original grant covers "openid offline_access" only; ask for an
	// additional scope the original consent did not authorise.
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {first.RefreshToken},
		"scope":         {"openid email"},
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
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, string(body))
	}
	body, _ := io.ReadAll(resp.Body)
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if got, _ := env["error"].(string); got != "invalid_scope" {
		t.Errorf("error=%q want invalid_scope (raw=%s)", got, string(body))
	}
	if _, hasAT := env["access_token"]; hasAT {
		t.Errorf("scope-upgrade rejection must not mint access_token: %v", env)
	}
}

// TestScenario_REF_006_ScopeUpgradeMultipleRejected verifies that a
// refresh_token request whose `scope` parameter contains multiple
// scopes not in the original grant is rejected with 400
// invalid_scope. Same envelope as REF-005 but with a wider
// upgrade-attempt surface.
//
// Spec: RFC 6749 §6.
func TestScenario_REF_006_ScopeUpgradeMultipleRejected(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-ref-006"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ref-006-secret"

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
	first := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if first.StatusCode != http.StatusOK || first.RefreshToken == "" {
		t.Fatalf("first /token must return refresh_token: status=%d body=%v", first.StatusCode, first.Raw)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {first.RefreshToken},
		"scope":         {"openid email profile"},
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
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, string(body))
	}
	body, _ := io.ReadAll(resp.Body)
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if got, _ := env["error"].(string); got != "invalid_scope" {
		t.Errorf("error=%q want invalid_scope (raw=%s)", got, string(body))
	}
	if _, hasAT := env["access_token"]; hasAT {
		t.Errorf("multi-scope-upgrade rejection must not mint access_token: %v", env)
	}
}

// TestScenario_REF_007_ScopeNarrowDropsOpenidNoIDToken verifies the
// negative half of OIDC Core §12: a refresh_token request that
// narrows the scope set and drops `openid` MUST receive 200 with an
// access_token but NO id_token. OIDC tokens are gated on the openid
// scope.
//
// Spec: RFC 6749 §6 + OIDC Core §12.
func TestScenario_REF_007_ScopeNarrowDropsOpenidNoIDToken(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-ref-007"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ref-007-secret"

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
		Scope:       "openid email offline_access",
		PKCE:        pkce,
	})
	first := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if first.StatusCode != http.StatusOK || first.RefreshToken == "" {
		t.Fatalf("first /token must return refresh_token: status=%d body=%v", first.StatusCode, first.Raw)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {first.RefreshToken},
		"scope":         {"email offline_access"},
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

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, string(body))
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if at, _ := env["access_token"].(string); at == "" {
		t.Error("narrowed-scope refresh missing access_token")
	}
	if idt, _ := env["id_token"].(string); idt != "" {
		t.Errorf("narrowed scope dropped openid; id_token must NOT be issued, got %q", idt)
	}
	scope, _ := env["scope"].(string)
	if strings.Contains(scope, "openid") {
		t.Errorf("scope=%q must NOT contain openid (narrowed request excluded it)", scope)
	}
}

// TestScenario_REF_008_ScopeNarrowKeepsOpenidIssuesIDToken verifies
// that a refresh_token request that narrows the scope set but keeps
// `openid` still receives an id_token alongside the access_token. The
// OP MUST honour scope narrowing without dropping OIDC ID Token
// issuance when the openid scope survives.
//
// Spec: RFC 6749 §6 (scope narrowing) + OIDC Core §12.
func TestScenario_REF_008_ScopeNarrowKeepsOpenidIssuesIDToken(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-ref-008"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ref-008-secret"

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
		Scope:       "openid email offline_access",
		PKCE:        pkce,
	})
	first := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if first.StatusCode != http.StatusOK || first.RefreshToken == "" {
		t.Fatalf("first /token must return refresh_token: status=%d body=%v", first.StatusCode, first.Raw)
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {first.RefreshToken},
		"scope":         {"openid offline_access"},
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

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, string(body))
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if at, _ := env["access_token"].(string); at == "" {
		t.Error("narrowed-scope refresh missing access_token")
	}
	if idt, _ := env["id_token"].(string); idt == "" {
		t.Errorf("narrowed-scope refresh keeps openid; id_token must still be issued (raw=%s)", string(body))
	}
	scope, _ := env["scope"].(string)
	if !strings.Contains(scope, "openid") {
		t.Errorf("scope=%q must still contain openid", scope)
	}
	if strings.Contains(scope, "email") {
		t.Errorf("scope=%q narrowed request dropped email; response must not re-add it", scope)
	}
}

func TestScenario_REF_009_RefreshAccountNotFoundRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-009")
}

// TestScenario_REF_010_RefreshTokenParamRequired verifies that a
// /token POST with grant_type=refresh_token but missing the
// refresh_token parameter is rejected with 400 invalid_request and an
// error_description that names refresh_token. The dispatcher MUST
// stop before any token-store lookup.
//
// Spec: RFC 6749 §6 / §5.2.
func TestScenario_REF_010_RefreshTokenParamRequired(t *testing.T) {
	t.Parallel()

	const clientID = "rp-ref-010"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ref-010-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/cb"},
		Scopes:                  []string{"openid", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})

	form := url.Values{"grant_type": {"refresh_token"}}
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
	if desc, _ := env["error_description"].(string); !strings.Contains(desc, "refresh_token") {
		t.Errorf("error_description=%q must mention refresh_token", desc)
	}
}

// TestScenario_REF_011_UnknownRefreshTokenRejected verifies that a
// well-formed but non-existent refresh_token value is rejected with
// 400 invalid_grant. The OP MUST NOT mint tokens for an unknown
// refresh_token.
//
// Spec: RFC 6749 §6 / §5.2 (invalid_grant covers "the provided
// authorization grant ... is invalid").
func TestScenario_REF_011_UnknownRefreshTokenRejected(t *testing.T) {
	t.Parallel()

	const clientID = "rp-ref-011"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ref-011-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/cb"},
		Scopes:                  []string{"openid", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})

	resp := postRefreshToken(t, tk, "rt-does-not-exist-1234567890", rp.ID, clientSecret)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", resp.StatusCode, resp.Raw)
	}
	if got, _ := resp.Raw["error"].(string); got != "invalid_grant" {
		t.Errorf("error=%q want invalid_grant (raw=%v)", got, resp.Raw)
	}
	if resp.AccessToken != "" || resp.IDToken != "" || resp.RefreshToken != "" {
		t.Errorf("unknown refresh_token must not mint tokens: %+v", resp.Raw)
	}
}

func TestScenario_REF_012_RotationEntitiesIncludeBothTokens(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-012")
}

// TestScenario_REF_013_RotationFirstRedemptionMintsNewToken
// exercises the refresh-token rotation contract: the first
// redemption emits a single token.refreshed audit event, the
// response carries a new refresh_token distinct from the original,
// and the rotated id_token preserves the nonce stamped on the
// originating authorization request.
//
// Spec: OIDC Core §12 / RFC 9700 §4.14.
func TestScenario_REF_013_RotationFirstRedemptionMintsNewToken(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-ref-013"
		callback = "https://rp.testkit.invalid/callback"
		nonce    = "n-REF-013-original-authz-nonce"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ref-013-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	audit := scenariokit.NewAuditCapture()
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithAuditLogger(audit.Logger()),
		op.WithStrictOfflineAccess(),
	))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid offline_access",
		Nonce:       nonce,
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
		t.Fatalf("first exchange missing refresh_token (offline_access scope?)")
	}
	if first.IDToken == "" {
		t.Fatal("first exchange missing id_token")
	}
	firstClaims := decodeScenarioJWTClaims(t, first.IDToken)
	if got := firstClaims["nonce"]; got != nonce {
		t.Fatalf("initial id_token nonce=%v want %q (precondition)", got, nonce)
	}

	rotated := postRefreshToken(t, tk, first.RefreshToken, rp.ID, clientSecret)
	if rotated.StatusCode != http.StatusOK {
		t.Fatalf("/token refresh status=%d body=%v, want 200", rotated.StatusCode, rotated.Raw)
	}

	// Rotation contract: the response MUST carry a new refresh_token
	// distinct from the presented one (RFC 9700 §4.14).
	if rotated.RefreshToken == "" {
		t.Fatal("rotated response missing refresh_token")
	}
	if rotated.RefreshToken == first.RefreshToken {
		t.Fatalf("rotated refresh_token must differ from original; got %q == %q", rotated.RefreshToken, first.RefreshToken)
	}

	// OIDC Core §12: the rotated id_token MUST preserve the original
	// nonce. This is the bug REF-013 anchors.
	if rotated.IDToken == "" {
		t.Fatal("rotated response missing id_token")
	}
	rotatedClaims := decodeScenarioJWTClaims(t, rotated.IDToken)
	if got := rotatedClaims["nonce"]; got != nonce {
		t.Fatalf("rotated id_token nonce=%v want %q (OIDC Core §12)", got, nonce)
	}

	// Audit surface: the rotation path emits exactly one
	// token.refreshed event. The catalog row was updated to reflect
	// the actually-emitted name (the previous wording cited
	// refresh_token.consumed / refresh_token.saved which the OP
	// does not emit today).
	refreshed := audit.EventsByName("token.refreshed")
	if len(refreshed) != 1 {
		t.Fatalf("token.refreshed events=%d want 1; events=%+v", len(refreshed), audit.Events())
	}
}

func TestScenario_REF_014_RotationDefaultScopeInheritsOriginal(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-014")
}

func TestScenario_REF_015_RotationNarrowedScopeRetainsOriginal(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-015")
}

func TestScenario_REF_016_RotationReplayRevokesGrantChain(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-016")
}

func TestScenario_REF_017_PredicateTrueRotationEntities(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-017")
}

func TestScenario_REF_018_PredicateTrueFirstRedemption(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-018")
}

func TestScenario_REF_019_PredicateTrueScopeInheritance(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-019")
}

func TestScenario_REF_020_PredicateTrueNarrowedScopeRequest(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-020")
}

func TestScenario_REF_021_PredicateTrueReplayRevokesChain(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-021")
}

func TestScenario_REF_022_PredicateFalseReusesRefreshToken(t *testing.T) {
	t.Parallel()
	t.Skip("pending: REF-022")
}
