package scenarios_test

// Catalog: test/scenarios/catalog/introspection.yaml (INT-NNN)
// Spec:
//   - RFC 7662 — OAuth 2.0 Token Introspection
//   - RFC 6749 §2.3 — Client Authentication
//   - RFC 8414 §2 — `introspection_endpoint` discovery metadata
//   - RFC 9068 §6 — JWT access tokens not introspectable
//   - RFC 9701 — JWT Response for OAuth Token Introspection (cross-ref)

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
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// TestScenario_INT_001_DiscoveryAdvertisesIntrospectionEndpoint
// checks the discovery surface: when the introspection feature is
// enabled, /.well-known/openid-configuration MUST list
// "introspection_endpoint" pointing at /oidc/introspect, and MUST also
// list "introspection_signing_alg_values_supported" with the OP's
// JWT-response algorithms. RFC 9701 JWT-formatted responses are
// available unconditionally whenever the endpoint is mounted, so the
// alg list ships together with the endpoint URL — there is no
// separate JWT-introspection feature toggle.
//
// Spec: RFC 8414 §2 / RFC 9701 §5.
func TestScenario_INT_001_DiscoveryAdvertisesIntrospectionEndpoint(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.Introspect)))

	_, _, doc := fetchDiscovery(t, tk.Server.URL)
	endpoint, _ := doc["introspection_endpoint"].(string)
	if endpoint == "" {
		t.Fatalf("introspection_endpoint missing when Introspect feature is on; doc=%v", doc)
	}
	if !strings.HasSuffix(endpoint, "/oidc/introspect") {
		t.Errorf("introspection_endpoint=%q must end with /oidc/introspect", endpoint)
	}
	algsRaw, present := doc["introspection_signing_alg_values_supported"]
	if !present {
		t.Fatalf("introspection_signing_alg_values_supported missing; RFC 9701 alg list ships with the endpoint")
	}
	algs, _ := algsRaw.([]any)
	hasES256 := false
	for _, a := range algs {
		if s, _ := a.(string); s == "ES256" {
			hasES256 = true
			break
		}
	}
	if !hasES256 {
		t.Errorf("introspection_signing_alg_values_supported=%v must include ES256 (the OP's only signing alg)", algs)
	}
}

// TestScenario_INT_002_AccessTokenIntrospectNoHint drives a full code
// → /token → /introspect round-trip for a confidential client and
// asserts that introspecting its own access token (without a
// token_type_hint) returns active=true with the metadata bundle RFC
// 7662 §2.2 names: client_id, scope, sub, iss, iat, exp,
// token_type=Bearer, and aud.
//
// Spec: RFC 7662 §2.2.
func TestScenario_INT_002_AccessTokenIntrospectNoHint(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-int-002"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-int-002-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.Introspect)))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
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
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.AccessToken == "" {
		t.Fatalf("/token status=%d body=%v, want 200 with access_token", tok.StatusCode, tok.Raw)
	}

	form := url.Values{"token": {tok.AccessToken}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /introspect request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}

	if active, _ := env["active"].(bool); !active {
		t.Fatalf("active=%v want true; body=%s", env["active"], string(body))
	}
	if got, _ := env["client_id"].(string); got != rp.ID {
		t.Errorf("client_id=%v want %q", env["client_id"], rp.ID)
	}
	if got, _ := env["sub"].(string); got != scenariokit.DefaultSubject {
		t.Errorf("sub=%v want %q", env["sub"], scenariokit.DefaultSubject)
	}
	if got, _ := env["iss"].(string); got != tk.Issuer {
		t.Errorf("iss=%v want %q", env["iss"], tk.Issuer)
	}
	if got, _ := env["token_type"].(string); got != "Bearer" {
		t.Errorf("token_type=%v want Bearer", env["token_type"])
	}
	if got, _ := env["scope"].(string); got == "" {
		t.Errorf("scope missing from active introspection: %v", env)
	}
	if _, ok := env["iat"].(float64); !ok {
		t.Errorf("iat must be a JSON number: %T", env["iat"])
	}
	if _, ok := env["exp"].(float64); !ok {
		t.Errorf("exp must be a JSON number: %T", env["exp"])
	}
	auds, _ := env["aud"].([]any)
	if len(auds) == 0 {
		// RFC 7662 allows aud as string OR array; accept either.
		if got, _ := env["aud"].(string); got == "" {
			t.Errorf("aud missing from active introspection: %v", env)
		}
	}
}

// TestScenario_INT_003_AccessTokenIntrospectCorrectHint mirrors
// INT-002 but supplies token_type_hint=access_token. RFC 7662 §2.1
// makes the hint advisory only — the endpoint MUST still resolve the
// access token and return active=true with the standard envelope.
//
// Spec: RFC 7662 §2.1.
func TestScenario_INT_003_AccessTokenIntrospectCorrectHint(t *testing.T) {
	t.Parallel()
	assertAccessTokenIntrospectActiveWithHint(t, "rp-int-003", "access_token")
}

// TestScenario_INT_004_AccessTokenIntrospectWrongHint supplies the
// wrong hint (token_type_hint=refresh_token) for an access token. The
// endpoint MUST treat the hint as an optimization hint only and still
// resolve the underlying access token, returning active=true.
//
// Spec: RFC 7662 §2.1.
func TestScenario_INT_004_AccessTokenIntrospectWrongHint(t *testing.T) {
	t.Parallel()
	assertAccessTokenIntrospectActiveWithHint(t, "rp-int-004", "refresh_token")
}

// TestScenario_INT_005_AccessTokenIntrospectUnrecognisedHint supplies
// a hint value the OP does not advertise. RFC 7662 §2.1 says the
// endpoint MUST ignore unrecognised hints rather than reject the
// request, so the response is the standard active=true envelope.
//
// Spec: RFC 7662 §2.1.
func TestScenario_INT_005_AccessTokenIntrospectUnrecognisedHint(t *testing.T) {
	t.Parallel()
	assertAccessTokenIntrospectActiveWithHint(t, "rp-int-005", "foobar")
}

// assertAccessTokenIntrospectActiveWithHint drives a code → /token →
// /introspect round-trip for a confidential client and asserts the
// hint-bearing introspection still returns active=true with at least
// the spec-required claims. The clientIDPrefix scopes the testkit
// fixture so parallel sub-tests do not collide.
func assertAccessTokenIntrospectActiveWithHint(t *testing.T, clientID, hint string) {
	t.Helper()

	const callback = "https://rp.testkit.invalid/callback"
	clientSecret := clientID + "-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.Introspect)))
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
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.AccessToken == "" {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}

	form := url.Values{
		"token":           {tok.AccessToken},
		"token_type_hint": {hint},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /introspect request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if active, _ := env["active"].(bool); !active {
		t.Fatalf("active=%v want true with hint=%q; body=%s", env["active"], hint, string(body))
	}
	if got, _ := env["client_id"].(string); got != rp.ID {
		t.Errorf("client_id=%v want %q", env["client_id"], rp.ID)
	}
	if got, _ := env["token_type"].(string); got != "Bearer" {
		t.Errorf("token_type=%v want Bearer", env["token_type"])
	}
}

// TestScenario_INT_006_RefreshTokenIntrospectNoHint drives a code →
// /token (offline_access) → /introspect round-trip and asserts that
// introspecting an opaque refresh token without a hint resolves
// against the refresh-token store and returns active=true plus the
// owning client_id, scope, and sub.
//
// Spec: RFC 7662 §2.2.
func TestScenario_INT_006_RefreshTokenIntrospectNoHint(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-int-006"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-int-006-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t,
		testkit.WithOptions(
			op.WithFeature(feature.Introspect),
			op.WithStrictOfflineAccess(),
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
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.RefreshToken == "" {
		t.Fatalf("/token status=%d body=%v, want 200 with refresh_token (offline_access scope?)", tok.StatusCode, tok.Raw)
	}

	form := url.Values{"token": {tok.RefreshToken}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /introspect request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if active, _ := env["active"].(bool); !active {
		t.Fatalf("active=%v want true; body=%s", env["active"], string(body))
	}
	if got, _ := env["client_id"].(string); got != rp.ID {
		t.Errorf("client_id=%v want %q", env["client_id"], rp.ID)
	}
	if got, _ := env["sub"].(string); got != scenariokit.DefaultSubject {
		t.Errorf("sub=%v want %q", env["sub"], scenariokit.DefaultSubject)
	}
	if got, _ := env["scope"].(string); !strings.Contains(got, "offline_access") {
		t.Errorf("scope=%q must include offline_access", got)
	}
}

// TestScenario_INT_007_RefreshTokenIntrospectCorrectHint mirrors
// INT-006 but supplies token_type_hint=refresh_token. The hint is
// advisory; the endpoint MUST still resolve the refresh token and
// return active=true.
//
// Spec: RFC 7662 §2.1.
func TestScenario_INT_007_RefreshTokenIntrospectCorrectHint(t *testing.T) {
	t.Parallel()
	assertRefreshTokenIntrospectActiveWithHint(t, "rp-int-007", "refresh_token")
}

// TestScenario_INT_008_RefreshTokenIntrospectWrongHint supplies the
// wrong hint (token_type_hint=access_token) for a refresh token. The
// endpoint MUST still resolve the underlying refresh token and return
// active=true.
//
// Spec: RFC 7662 §2.1.
func TestScenario_INT_008_RefreshTokenIntrospectWrongHint(t *testing.T) {
	t.Parallel()
	assertRefreshTokenIntrospectActiveWithHint(t, "rp-int-008", "access_token")
}

// TestScenario_INT_009_RefreshTokenIntrospectUnrecognisedHint supplies
// a hint value the OP does not advertise. RFC 7662 §2.1 requires the
// endpoint to ignore unrecognised hints and still resolve the token.
//
// Spec: RFC 7662 §2.1.
func TestScenario_INT_009_RefreshTokenIntrospectUnrecognisedHint(t *testing.T) {
	t.Parallel()
	assertRefreshTokenIntrospectActiveWithHint(t, "rp-int-009", "foobar")
}

// assertRefreshTokenIntrospectActiveWithHint drives a code →
// /token (offline_access) → /introspect round-trip and asserts that
// the hint-bearing introspection of the resulting refresh token still
// returns active=true with the standard claim subset.
func assertRefreshTokenIntrospectActiveWithHint(t *testing.T, clientID, hint string) {
	t.Helper()

	const callback = "https://rp.testkit.invalid/callback"
	clientSecret := clientID + "-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t,
		testkit.WithOptions(
			op.WithFeature(feature.Introspect),
			op.WithStrictOfflineAccess(),
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
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.RefreshToken == "" {
		t.Fatalf("/token status=%d body=%v, want refresh_token", tok.StatusCode, tok.Raw)
	}

	form := url.Values{
		"token":           {tok.RefreshToken},
		"token_type_hint": {hint},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /introspect request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if active, _ := env["active"].(bool); !active {
		t.Fatalf("active=%v want true with hint=%q; body=%s", env["active"], hint, string(body))
	}
	if got, _ := env["client_id"].(string); got != rp.ID {
		t.Errorf("client_id=%v want %q", env["client_id"], rp.ID)
	}
	if got, _ := env["scope"].(string); !strings.Contains(got, "offline_access") {
		t.Errorf("scope=%q must include offline_access", got)
	}
}

// TestScenario_INT_010_ClientCredentialsIntrospectNoHint mints an
// access token via grant_type=client_credentials, then introspects it
// without a token_type_hint and asserts active=true with at least the
// client_id present. The grant has no end-user resource owner, so
// v1.0 sets sub=client_id (RFC 9068 §2.2 / FAPI 2.0 baseline,
// internal/tokenendpoint/clientcred.go); the test pins this shape
// because RPs can rely on it to distinguish a cc token from a
// user-bound token without reading the access token format.
//
// Spec: RFC 7662 §2.2 / RFC 6749 §4.4.
func TestScenario_INT_010_ClientCredentialsIntrospectNoHint(t *testing.T) {
	t.Parallel()

	const clientID = "rp-int-010"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-int-010-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t,
		testkit.WithOptions(
			op.WithFeature(feature.Introspect),
			op.WithAccessTokenFormat(op.AccessTokenFormatOpaque),
		),
	)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		Scopes:                  []string{"api"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"client_credentials"},
	})

	// Mint a client_credentials access token.
	tokenForm := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"api"},
	}
	tokenReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(tokenForm.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth(rp.ID, clientSecret)

	tokenResp, err := tk.HTTPClient(nil).Do(tokenReq)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	tokenBody, _ := io.ReadAll(tokenResp.Body)
	_ = tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d want 200 body=%s", tokenResp.StatusCode, tokenBody)
	}
	var tokenEnv map[string]any
	if err := json.Unmarshal(tokenBody, &tokenEnv); err != nil {
		t.Fatalf("/token body is not JSON: %v (raw=%s)", err, tokenBody)
	}
	at, _ := tokenEnv["access_token"].(string)
	if at == "" {
		t.Fatalf("/token missing access_token: %s", tokenBody)
	}

	// Introspect without a hint.
	introForm := url.Values{"token": {at}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(introForm.Encode()))
	if err != nil {
		t.Fatalf("build /introspect request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if active, _ := env["active"].(bool); !active {
		t.Fatalf("active=%v want true; body=%s", env["active"], string(body))
	}
	if got, _ := env["client_id"].(string); got != rp.ID {
		t.Errorf("client_id=%v want %q", env["client_id"], rp.ID)
	}
	// v1.0 contract: cc grants set sub=client_id since there is no
	// end user. This pins the projection so RPs can rely on it.
	if got, _ := env["sub"].(string); got != rp.ID {
		t.Errorf("sub=%v want %q (cc grant: sub=client_id)", env["sub"], rp.ID)
	}
	if got, _ := env["token_type"].(string); got != "Bearer" {
		t.Errorf("token_type=%v want Bearer", env["token_type"])
	}
}

func TestScenario_INT_011_ClientCredentialsIntrospectCorrectHint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: INT-011")
}

func TestScenario_INT_012_ClientCredentialsIntrospectUnrecognisedHint(t *testing.T) {
	t.Parallel()
	t.Skip("pending: INT-012")
}

// TestScenario_INT_013_StructuredJWTRejectedAtIntrospection is OOS — see catalog out_of_scope_reason.
func TestScenario_INT_013_StructuredJWTRejectedAtIntrospection(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: INT-013 (see catalog out_of_scope_reason)")
}

// TestScenario_INT_014_PairwiseClientReceivesPairwiseSub is OOS — see catalog out_of_scope_reason.
func TestScenario_INT_014_PairwiseClientReceivesPairwiseSub(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: INT-014 (see catalog out_of_scope_reason)")
}

func TestScenario_INT_015_RSIntrospectionRespectsTokenSubjectType(t *testing.T) {
	t.Parallel()
	t.Skip("pending: INT-015")
}

// TestScenario_INT_016_ResponseCarriesNoStore confirms that every
// /introspect response carries `Cache-Control: no-store`. RFC 7662 §4
// makes this MUST: the introspection envelope is a snapshot of token
// state and may not be reused, so caching agents must be told to drop
// it. The check fires on a successful active=true response so the
// header lives on the success path (the inactive branch is
// straightforward by inspection of the same handler).
//
// Spec: RFC 7662 §4.
func TestScenario_INT_016_ResponseCarriesNoStore(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-int-016"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-int-016-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.Introspect)))
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
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.AccessToken == "" {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}

	form := url.Values{"token": {tok.AccessToken}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /introspect request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	cacheControl := resp.Header.Get("Cache-Control")
	if !strings.Contains(cacheControl, "no-store") {
		t.Errorf("Cache-Control=%q must contain no-store", cacheControl)
	}
}

// TestScenario_INT_017_MissingTokenParameterRejected POSTs an
// authenticated /introspect request whose form body omits the `token`
// parameter entirely. RFC 7662 §2.1 makes `token` REQUIRED; the OP
// MUST reject the call with 400 invalid_request and an
// error_description that names the missing parameter so an embedder
// can self-correct without guessing.
//
// Spec: RFC 7662 §2.1.
func TestScenario_INT_017_MissingTokenParameterRejected(t *testing.T) {
	t.Parallel()

	const clientID = "rp-int-017"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-int-017-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.Introspect)))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	form := url.Values{}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /introspect request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if got, _ := env["error"].(string); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (raw=%s)", got, string(body))
	}
	desc, _ := env["error_description"].(string)
	if !strings.Contains(desc, "token") {
		t.Errorf("error_description=%q must name the missing 'token' parameter", desc)
	}
}

// TestScenario_INT_018_NonsenseTokenReturnsActiveFalse confirms that
// an authenticated client submitting an arbitrary, unrelated string
// as the token parameter receives 200 with body {"active": false}.
// RFC 7662 §2.2 requires the inactive shape to omit every other
// claim so a probing client cannot infer anything about the token's
// existence.
//
// Spec: RFC 7662 §2.2.
func TestScenario_INT_018_NonsenseTokenReturnsActiveFalse(t *testing.T) {
	t.Parallel()

	const clientID = "rp-int-018"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-int-018-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.Introspect)))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	form := url.Values{"token": {"this-token-was-never-issued-by-the-op"}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /introspect request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if active, _ := env["active"].(bool); active {
		t.Fatalf("active=true for unknown token; body=%s", string(body))
	}
	for _, leak := range []string{"sub", "client_id", "scope", "iat", "exp", "iss", "token_type", "aud", "jti"} {
		if _, present := env[leak]; present {
			t.Errorf("inactive response leaked %q: %v", leak, env)
		}
	}
}

// TestScenario_INT_019_PublicClientCannotInspectOtherTokens
// verifies the same-client-only introspection policy: a public client
// (token_endpoint_auth_method=none) submitting another client's
// access token receives 200 {"active": false} only — no claims, no
// hints about whether the token exists. The OP MUST collapse
// "wrong owner" onto the inactive envelope so a public probe cannot
// enumerate live tokens issued to other clients.
//
// Spec: RFC 7662 §2.2 (single inactive envelope) plus the OP's
// same-client-only policy documented in introspectendpoint/doc.go.
func TestScenario_INT_019_PublicClientCannotInspectOtherTokens(t *testing.T) {
	t.Parallel()

	const (
		ownerID       = "rp-int-019-owner"
		ownerCallback = "https://rp.testkit.invalid/owner"
		ownerSecret   = "rp-int-019-owner-secret" //nolint:gosec // test fixture
		probePublicID = "rp-int-019-public-probe"
		probePublicCB = "https://rp.testkit.invalid/probe"
	)

	ownerHash, err := op.HashClientSecret(ownerSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.Introspect)))
	owner := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      ownerID,
		SecretHash:              ownerHash,
		RedirectURIs:            []string{ownerCallback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})
	probe := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      probePublicID,
		RedirectURIs:            []string{probePublicCB},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code"},
		PublicClient:            true,
	})

	// Mint an access token for the OWNER client through a full code flow.
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    owner.ID,
		RedirectURI: ownerCallback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  ownerCallback,
		Verifier:     pkce.Verifier,
		ClientID:     owner.ID,
		ClientSecret: ownerSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.AccessToken == "" {
		t.Fatalf("/token status=%d body=%v, want 200 with access_token", tok.StatusCode, tok.Raw)
	}

	// PROBE the owner's access token from the PUBLIC client. The body
	// carries client_id (no Authorization header) since the public
	// client has token_endpoint_auth_method=none.
	form := url.Values{
		"token":     {tok.AccessToken},
		"client_id": {probe.ID},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /introspect request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200; body=%s", resp.StatusCode, raw)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if active, _ := env["active"].(bool); active {
		t.Fatalf("active=true; cross-client introspection MUST collapse onto {active:false}; body=%s", string(body))
	}
	// Inactive envelope is the canonical single-key body. Any extra
	// claim (client_id, sub, scope, exp, ...) leaks token existence.
	for _, leak := range []string{"client_id", "sub", "scope", "iss", "exp", "iat", "token_type", "username"} {
		if _, present := env[leak]; present {
			t.Errorf("inactive body leaks %q=%v (RFC 7662 §2.2 requires bare {active:false})", leak, env[leak])
		}
	}
}

// TestScenario_INT_020_BadClientAuthEmitsAuditError drives a
// /introspect POST whose Basic-auth header carries the right
// client_id but the wrong secret. The OP MUST reject with 401
// invalid_client AND emit a single "introspection.error" audit event
// carrying the failing client_id so SOC tooling can detect probing
// for a known client_id even though the wire response stays generic.
//
// Spec: RFC 6749 §2.3 / RFC 7662 §2.1.
func TestScenario_INT_020_BadClientAuthEmitsAuditError(t *testing.T) {
	t.Parallel()

	const clientID = "rp-int-020"
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-int-020-correct-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	auditCap := scenariokit.NewAuditCapture()
	tk := testkit.NewProvider(t,
		testkit.WithOptions(
			op.WithFeature(feature.Introspect),
			op.WithAuditLogger(auditCap.Logger()),
		),
	)
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	form := url.Values{"token": {"any-value"}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /introspect request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, "wrong-secret")

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}

	events := auditCap.EventsByName(string(op.AuditIntrospectionError))
	if len(events) != 1 {
		t.Fatalf("got %d %q events, want exactly 1; all=%+v",
			len(events), op.AuditIntrospectionError, auditCap.Events())
	}
	ev := events[0]
	var gotClientID string
	for _, attr := range ev.Attrs {
		if attr.Key == "client_id" {
			gotClientID = attr.Value.String()
			break
		}
	}
	if gotClientID != clientID {
		t.Errorf("audit event client_id=%q want %q (attrs=%+v)",
			gotClientID, clientID, ev.Attrs)
	}
}

// TestScenario_INT_021_AuthorizationCodeIsNotIntrospectable mints a
// fresh authorization code via the code flow and submits it to the
// introspection endpoint as the token parameter. RFC 7662's
// introspection contract covers access and refresh tokens only;
// authorization codes are a transient grant artefact and MUST resolve
// to {"active": false} so a probing client cannot use the
// introspection endpoint to enumerate live codes.
//
// Spec: RFC 7662 §2.2 (token semantics — codes are not tokens).
func TestScenario_INT_021_AuthorizationCodeIsNotIntrospectable(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-int-021"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-int-021-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.Introspect)))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	form := url.Values{"token": {flow.Code}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /introspect request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if active, _ := env["active"].(bool); active {
		t.Fatalf("active=true for authorization code; codes are not introspectable. body=%s", string(body))
	}
	for _, leak := range []string{"sub", "client_id", "scope", "iat", "exp", "iss", "token_type", "jti"} {
		if _, present := env[leak]; present {
			t.Errorf("inactive code response leaked %q: %v", leak, env)
		}
	}
}

// TestScenario_INT_022_ExpiredAccessTokenReturnsActiveFalse confirms
// that an access token presented after its exp has elapsed resolves
// to {"active": false} on the introspection endpoint. The wall clock
// is driven via [op.Clock] so the test does not sleep.
//
// Spec: RFC 7662 §2.2.
func TestScenario_INT_022_ExpiredAccessTokenReturnsActiveFalse(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-int-022"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-int-022-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	clock := newAdvanceableClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithFeature(feature.Introspect),
			op.WithAccessTokenTTL(2*time.Minute),
		),
	)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid",
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
	if tok.StatusCode != http.StatusOK || tok.AccessToken == "" {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}

	// Push past WithAccessTokenTTL so the introspector observes exp <= now.
	clock.Advance(10 * time.Minute)

	form := url.Values{"token": {tok.AccessToken}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /introspect request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if active, _ := env["active"].(bool); active {
		t.Fatalf("active=true for expired access token; body=%s", string(body))
	}
	for _, leak := range []string{"sub", "client_id", "scope", "iat", "exp", "iss", "token_type", "jti"} {
		if _, present := env[leak]; present {
			t.Errorf("inactive expired-token response leaked %q: %v", leak, env)
		}
	}
}

// TestScenario_INT_023_ConsumedRefreshTokenReturnsActiveFalse drives a
// code → /token (offline_access) round-trip, then exchanges the
// resulting refresh token for a fresh pair to consume it via rotation,
// and finally asserts that introspecting the *original* refresh token
// returns 200 {"active": false} with no metadata leaked. RFC 7662 §2.2
// requires inactive tokens to surface only the active=false envelope so
// a probing client cannot infer that the token ever existed.
//
// Spec: RFC 7662 §2.2 / RFC 6749 §6.
func TestScenario_INT_023_ConsumedRefreshTokenReturnsActiveFalse(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-int-023"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-int-023-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t,
		testkit.WithOptions(
			op.WithFeature(feature.Introspect),
			op.WithStrictOfflineAccess(),
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
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: clientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.RefreshToken == "" {
		t.Fatalf("/token status=%d body=%v, want 200 with refresh_token (offline_access scope?)", tok.StatusCode, tok.Raw)
	}
	originalRefresh := tok.RefreshToken

	// Consume the original refresh token by rotating it through /token.
	rotateForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {originalRefresh},
	}
	rotateReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(rotateForm.Encode()))
	if err != nil {
		t.Fatalf("build /token rotate request: %v", err)
	}
	rotateReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rotateReq.SetBasicAuth(rp.ID, clientSecret)

	rotateResp, err := tk.HTTPClient(nil).Do(rotateReq)
	if err != nil {
		t.Fatalf("POST /token rotate: %v", err)
	}
	rotateBody, _ := io.ReadAll(rotateResp.Body)
	_ = rotateResp.Body.Close()
	if rotateResp.StatusCode != http.StatusOK {
		t.Fatalf("rotate /token status=%d want 200 body=%s", rotateResp.StatusCode, rotateBody)
	}

	form := url.Values{"token": {originalRefresh}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /introspect request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if active, _ := env["active"].(bool); active {
		t.Fatalf("active=true for consumed refresh token; body=%s", string(body))
	}
	for _, leak := range []string{"sub", "client_id", "scope", "iat", "exp", "iss", "token_type", "aud", "jti"} {
		if _, present := env[leak]; present {
			t.Errorf("inactive consumed-refresh response leaked %q: %v", leak, env)
		}
	}
}

// TestScenario_INT_024_AdapterTypeMismatchHandledSafely posts a fresh
// authorization code to /introspect with token_type_hint=refresh_token,
// forcing the resolver to enter the refresh-token branch first. Codes
// and refresh tokens live in different substores; if the storage
// adapter were to mistakenly resolve a code under a refresh-token
// lookup the response would leak refresh-token-shaped claims (sub,
// scope, client_id, ...). The endpoint MUST instead surface the
// canonical {"active": false} envelope and avoid any type confusion
// between grant artefacts. INT-021 covers the default-hint path; this
// row pins down the explicit refresh-hint variant.
//
// Spec: RFC 7662 §2.2 (only access / refresh tokens are introspectable).
func TestScenario_INT_024_AdapterTypeMismatchHandledSafely(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-int-024"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-int-024-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.Introspect)))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}

	// Submit the still-unredeemed authorization code as if it were a
	// refresh token. token_type_hint forces the resolver to try the
	// refresh-token (opaque) branch first per RFC 7662 §2.1.
	form := url.Values{
		"token":           {flow.Code},
		"token_type_hint": {"refresh_token"},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /introspect request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rp.ID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /introspect: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if active, _ := env["active"].(bool); active {
		t.Fatalf("active=true for authorization code under hint=refresh_token; "+
			"resolver may have type-confused a code as a refresh token. body=%s", string(body))
	}
	for _, leak := range []string{"sub", "client_id", "scope", "iat", "exp", "iss", "token_type", "aud", "jti"} {
		if _, present := env[leak]; present {
			t.Errorf("inactive code-as-refresh response leaked %q: %v", leak, env)
		}
	}
}

// TestScenario_INT_025_AccessTokenSuccessRegistersEntities is OOS — see catalog out_of_scope_reason.
func TestScenario_INT_025_AccessTokenSuccessRegistersEntities(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: INT-025 (see catalog out_of_scope_reason)")
}

// TestScenario_INT_026_RefreshTokenSuccessRegistersEntities is OOS — see catalog out_of_scope_reason.
func TestScenario_INT_026_RefreshTokenSuccessRegistersEntities(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: INT-026 (see catalog out_of_scope_reason)")
}

// TestScenario_INT_027_ClientCredentialsSuccessRegistersEntities is OOS — see catalog out_of_scope_reason.
func TestScenario_INT_027_ClientCredentialsSuccessRegistersEntities(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: INT-027 (see catalog out_of_scope_reason)")
}
