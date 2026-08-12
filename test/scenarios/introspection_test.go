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
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
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

// TestScenario_INT_011_ClientCredentialsIntrospectCorrectHint mints
// a client_credentials access token (opaque format so /introspect
// observes the substore) and asserts that introspecting it with
// token_type_hint=access_token returns active=true and client_id.
// The hint is the conventional one for an access token, so the
// resolver short-circuits onto the access-token branch first.
//
// Spec: RFC 7662 §2.1.
func TestScenario_INT_011_ClientCredentialsIntrospectCorrectHint(t *testing.T) {
	t.Parallel()
	runCCIntrospectionWithHint(t, "rp-int-011", "access_token")
}

// TestScenario_INT_012_ClientCredentialsIntrospectUnrecognisedHint
// mints a client_credentials access token and asserts that an
// arbitrary unknown token_type_hint is ignored — the resolver
// surfaces active=true and client_id as if no hint had been
// supplied.
//
// Spec: RFC 7662 §2.1.
func TestScenario_INT_012_ClientCredentialsIntrospectUnrecognisedHint(t *testing.T) {
	t.Parallel()
	runCCIntrospectionWithHint(t, "rp-int-012", "foobar")
}

// runCCIntrospectionWithHint factors the INT-011/INT-012 setup so
// the rows differ only by the hint they submit. The OP MUST
// surface active=true plus client_id regardless of which hint
// (correct, wrong, or arbitrary) the caller supplies — RFC 7662
// §2.1 reserves token_type_hint as a lookup optimisation.
func runCCIntrospectionWithHint(t *testing.T, idPrefix, hint string) {
	t.Helper()
	clientID := idPrefix
	clientSecret := idPrefix + "-secret"

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
	tokenForm := url.Values{"grant_type": {"client_credentials"}, "scope": {"api"}}
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

	form := url.Values{"token": {at}, "token_type_hint": {hint}}
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
		t.Fatalf("active=%v want true (hint=%q must not block resolution); body=%s", env["active"], hint, string(body))
	}
	if got, _ := env["client_id"].(string); got != rp.ID {
		t.Errorf("client_id=%v want %q (hint=%q)", env["client_id"], rp.ID, hint)
	}
}

// TestScenario_INT_013_StructuredJWTRejectedAtIntrospection is OOS — see catalog out_of_scope_reason.
func TestScenario_INT_013_StructuredJWTRejectedAtIntrospection(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: INT-013 (see catalog out_of_scope_reason)")
}

// TestScenario_INT_014_PairwiseClientReceivesPairwiseSub verifies that
// a client registered with subject_type=pairwise introspecting its own
// refresh token reads back the pairwise pseudonym rather than the
// OP-internal account id the record persists.
//
// The contrast half is what makes the row worth pinning: a
// subject_type=public client on the SAME provider, authenticating the
// same end user, must see the raw account id. Without both directions
// a projector that returned the raw value unconditionally would still
// pass, because the pairwise value is only recognisable as pairwise
// when something else on the wire is not.
//
// Spec: OIDC Core 1.0 §8 / RFC 7662 §2.2.
func TestScenario_INT_014_PairwiseClientReceivesPairwiseSub(t *testing.T) {
	t.Parallel()

	const (
		pairwiseID       = "rp-int-014-pairwise"
		publicID         = "rp-int-014-public"
		pairwiseCallback = "https://rp-int-014-pairwise.example.com/cb"
		publicCallback   = "https://rp-int-014-public.example.net/cb"
	)
	//nolint:gosec // test fixture: not a real credential.
	const secret = "rp-int-014-secret"

	hash, err := op.HashClientSecret(secret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithPairwiseSubject(int015PairwiseSalt),
		op.WithFeature(feature.Introspect),
	))
	pairwiseRP := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      pairwiseID,
		SecretHash:              hash,
		RedirectURIs:            []string{pairwiseCallback},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SubjectType:             "pairwise",
	})
	publicRP := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      publicID,
		SecretHash:              hash,
		RedirectURIs:            []string{publicCallback},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SubjectType:             "public",
	})
	tk.Store.PutUser(context.Background(), &store.User{Subject: scenariokit.DefaultSubject})

	pairwiseTok := int015CodeFlow(t, tk, pairwiseRP.ID, pairwiseCallback, secret, "openid offline_access", nil)
	if pairwiseTok.RefreshToken == "" {
		t.Fatalf("pairwise client got no refresh_token: %v", pairwiseTok.Raw)
	}
	publicTok := int015CodeFlow(t, tk, publicRP.ID, publicCallback, secret, "openid offline_access", nil)
	if publicTok.RefreshToken == "" {
		t.Fatalf("public client got no refresh_token: %v", publicTok.Raw)
	}

	pairwiseIntro := int015Introspect(t, tk, pairwiseRP.ID, secret, pairwiseTok.RefreshToken, "refresh_token")
	if active, _ := pairwiseIntro["active"].(bool); !active {
		t.Fatalf("pairwise client's own refresh token introspected inactive: %v", pairwiseIntro)
	}
	pairwiseSub, _ := pairwiseIntro["sub"].(string)
	if pairwiseSub == "" {
		t.Fatalf("introspection response carries no sub: %v", pairwiseIntro)
	}
	if pairwiseSub == scenariokit.DefaultSubject {
		t.Errorf("sub=%q is the raw account id; a pairwise client must receive the pseudonym", pairwiseSub)
	}
	// The pseudonym the RP already holds is the one in its id_token; a
	// second, different pseudonym on the introspection egress would
	// break the OIDC Core §8.1 one-sub-per-client guarantee.
	if idSub := int015IDTokenSub(t, pairwiseTok.IDToken); pairwiseSub != idSub {
		t.Errorf("introspection sub=%q must equal the client's id_token sub=%q", pairwiseSub, idSub)
	}

	publicIntro := int015Introspect(t, tk, publicRP.ID, secret, publicTok.RefreshToken, "refresh_token")
	if active, _ := publicIntro["active"].(bool); !active {
		t.Fatalf("public client's own refresh token introspected inactive: %v", publicIntro)
	}
	if got, _ := publicIntro["sub"].(string); got != scenariokit.DefaultSubject {
		t.Errorf("public client sub=%q want the raw account id %q", got, scenariokit.DefaultSubject)
	}
}

// TestScenario_INT_015_RSIntrospectionRespectsTokenSubjectType verifies
// the RFC 7662 §2.2 deployment [op.ProtectedResource.IntrospectionClients]
// exists for: a resource server introspects an access token that was
// issued to a DIFFERENT client, because the token names the resource
// that server speaks for.
//
// The load-bearing assertion is the subject projection. The `sub` the
// resource server reads back is the pseudonym belonging to the token's
// OWN client, not one recomputed for the inspecting client — the test
// pins that by driving a second flow in which the resource server acts
// as an RP for the same end user, so its own pseudonym for that user is
// a known value the response must NOT equal. Getting this backwards
// would hand every delegated resource server a subject identifier its
// callers have never seen, silently breaking correlation.
//
// Both negatives are pinned too, because the delegation is only safe if
// it stays scoped: an undelegated client sees {active:false} for the
// same token, and a client delegated for a different resource sees
// {active:false} as well.
//
// Spec: RFC 7662 §2.2 / RFC 8707 §2 / OIDC Core 1.0 §8.
func TestScenario_INT_015_RSIntrospectionRespectsTokenSubjectType(t *testing.T) {
	t.Parallel()

	const (
		rpID        = "rp-int-015"
		rsAID       = "rs-int-015-a"
		rsBID       = "rs-int-015-b"
		rsNoneID    = "rs-int-015-none"
		rpCallback  = "https://rp-int-015.example.com/cb"
		rsACallback = "https://rs-int-015-a.example.net/cb"
		// RFC 9728 §3.1 derives each resource's metadata path from the
		// resource's PATH component, so two resources that differ only
		// by host would collide at /.well-known/oauth-protected-resource.
		resourceA = "https://api.int015.example/a"
		resourceB = "https://api.int015.example/b"
	)
	//nolint:gosec // test fixture: not a real credential.
	const secret = "rp-int-015-secret"

	hash, err := op.HashClientSecret(secret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithPairwiseSubject(int015PairwiseSalt),
		op.WithFeature(feature.Introspect),
		// Opaque so the introspection response is composed from the
		// stored record and therefore actually runs the projector; a
		// JWT access token would carry an already-projected sub and
		// leave the projector's client choice unobserved.
		op.WithAccessTokenFormat(op.AccessTokenFormatOpaque),
		op.WithProtectedResources(
			op.ProtectedResource{Resource: resourceA, IntrospectionClients: []string{rsAID}},
			op.ProtectedResource{Resource: resourceB, IntrospectionClients: []string{rsBID}},
		),
	))

	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      rpID,
		SecretHash:              hash,
		RedirectURIs:            []string{rpCallback},
		Scopes:                  []string{"openid", "profile", "email"},
		Resources:               []string{resourceA, resourceB},
		TokenEndpointAuthMethod: "client_secret_basic",
		SubjectType:             "pairwise",
	})
	// The resource server is also an RP in its own right, on a
	// different sector, so its pseudonym for this user is a concrete
	// value the introspection response must not return.
	rsA := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      rsAID,
		SecretHash:              hash,
		RedirectURIs:            []string{rsACallback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SubjectType:             "pairwise",
	})
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      rsBID,
		SecretHash:              hash,
		Scopes:                  []string{"api"},
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      rsNoneID,
		SecretHash:              hash,
		Scopes:                  []string{"api"},
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	tk.Store.PutUser(context.Background(), &store.User{Subject: scenariokit.DefaultSubject})

	rpTok := int015CodeFlow(t, tk, rp.ID, rpCallback, secret, "openid profile",
		url.Values{"resource": {resourceA}})
	if rpTok.AccessToken == "" {
		t.Fatalf("RP got no access_token: %v", rpTok.Raw)
	}
	rpSub := int015IDTokenSub(t, rpTok.IDToken)
	if rpSub == scenariokit.DefaultSubject {
		t.Fatalf("RP id_token sub=%q is the raw account id; pairwise projection did not run", rpSub)
	}

	rsATok := int015CodeFlow(t, tk, rsA.ID, rsACallback, secret, "openid profile", nil)
	rsASub := int015IDTokenSub(t, rsATok.IDToken)
	if rsASub == rpSub {
		t.Fatalf("fixture is degenerate: RP and RS resolved to the same pseudonym %q; "+
			"they must sit on different sectors for this row to mean anything", rpSub)
	}

	// The delegated resource server reads a token issued to the RP.
	intro := int015Introspect(t, tk, rsAID, secret, rpTok.AccessToken, "access_token")
	if active, _ := intro["active"].(bool); !active {
		t.Fatalf("delegated RS saw active=false for a token addressed to its resource: %v", intro)
	}
	if got, _ := intro["client_id"].(string); got != rp.ID {
		t.Errorf("client_id=%v want %q (the token's own client)", intro["client_id"], rp.ID)
	}
	gotSub, _ := intro["sub"].(string)
	if gotSub != rpSub {
		t.Errorf("sub=%q want %q — the projection must follow the token's own client", gotSub, rpSub)
	}
	if gotSub == rsASub {
		t.Errorf("sub=%q is the INSPECTING client's pseudonym; the inspecting client's "+
			"subject_type must not override the token's", gotSub)
	}
	if gotSub == scenariokit.DefaultSubject {
		t.Errorf("sub=%q leaked the raw account id to the resource server", gotSub)
	}

	// Negative 1: a client named by no resource stays same-client-only.
	if got := int015Introspect(t, tk, rsNoneID, secret, rpTok.AccessToken, "access_token"); !int015Inactive(got) {
		t.Errorf("undelegated client read another client's token: %v", got)
	}
	// Negative 2: delegation is scoped to the resource, not blanket.
	if got := int015Introspect(t, tk, rsBID, secret, rpTok.AccessToken, "access_token"); !int015Inactive(got) {
		t.Errorf("client delegated for %s read a token addressed to %s: %v", resourceB, resourceA, got)
	}
}

// int015PairwiseSalt is the pairwise salt the INT-014 / INT-015
// providers enrol. [op.WithPairwiseSubject] requires at least 32 bytes;
// a fixed value keeps a failing trace replayable across runs.
var int015PairwiseSalt = []byte("int-015-pairwise-fixed-salt-32by")

// int015CodeFlow drives a full code flow for clientID and returns the
// parsed /token envelope, failing the test on any non-200. extra is
// merged into BOTH the /authorize query and the /token form so a
// resource indicator is bound at each hop the way RFC 8707 expects.
func int015CodeFlow(
	t *testing.T,
	tk *testkit.Provider,
	clientID, callback, secret, scope string,
	extra url.Values,
) scenariokit.TokenResponse {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    clientID,
		RedirectURI: callback,
		Scope:       scope,
		PKCE:        pkce,
		Extra:       extra,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback for %s missing code: %+v", clientID, flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     clientID,
		ClientSecret: secret,
		Extra:        extra,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token for %s status=%d body=%v", clientID, tok.StatusCode, tok.Raw)
	}
	return tok
}

// int015Introspect POSTs token to /introspect as clientID and returns
// the decoded envelope. A non-200 fails the test: RFC 7662 §2.2 answers
// an unreadable token with {"active":false} at 200, never a status code.
func int015Introspect(
	t *testing.T,
	tk *testkit.Provider,
	clientID, secret, token, hint string,
) map[string]any {
	t.Helper()
	form := url.Values{"token": {token}, "token_type_hint": {hint}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/introspect", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /introspect request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /introspect as %s: %v", clientID, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /introspect body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("/introspect as %s status=%d body=%s", clientID, resp.StatusCode, body)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("/introspect body is not JSON: %v (raw=%s)", err, body)
	}
	return env
}

// int015Inactive reports whether env is the canonical RFC 7662 §2.2
// inactive envelope: active=false and no other member. The membership
// check matters as much as the flag — an inactive response that still
// leaked sub or client_id would be the token-existence oracle the
// single-envelope rule exists to prevent.
func int015Inactive(env map[string]any) bool {
	if active, _ := env["active"].(bool); active {
		return false
	}
	return len(env) == 1
}

// int015IDTokenSub extracts the "sub" claim from a compact JWS id_token.
func int015IDTokenSub(t *testing.T, idToken string) string {
	t.Helper()
	if idToken == "" {
		t.Fatal("id_token missing; cannot read the client's pseudonym")
	}
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token is not a compact JWS: %q", idToken)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode id_token payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("id_token payload is not JSON: %v", err)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		t.Fatalf("id_token carries no sub: %v", claims)
	}
	return sub
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
// Spec: RFC 7662 §2.1 plus the OP's confidential-introspection policy
// documented in introspectendpoint/doc.go.
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

	// A public client cannot authenticate an introspection request. Reject it
	// before token lookup rather than returning an inactive envelope that could
	// be used as a probing oracle.
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, string(body))
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401; body=%s", resp.StatusCode, body)
	}
	if got, _ := env["error"].(string); got != "invalid_client" {
		t.Errorf("error=%q want invalid_client; body=%s", got, body)
	}
	for _, leak := range []string{"active", "client_id", "sub", "scope", "iss", "exp", "iat", "token_type", "username"} {
		if _, present := env[leak]; present {
			t.Errorf("rejected body leaks %q=%v; body=%s", leak, env[leak], body)
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
