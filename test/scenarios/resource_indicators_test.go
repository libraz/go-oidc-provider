package scenarios_test

// Catalog: test/scenarios/catalog/resource_indicators.yaml (RI-NNN)
// Spec:
//   - RFC 8707 — Resource Indicators for OAuth 2.0
//   - RFC 6749 §4.1, §4.4, §6
//   - RFC 8628 — OAuth 2.0 Device Authorization Grant
//   - RFC 9126 — OAuth 2.0 Pushed Authorization Requests
//   - OpenID Connect CIBA Core 1.0
//   - OIDC Core 1.0 §5.3 (UserInfo)

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

func TestScenario_RI_001_DefaultResourceHookExposed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-001")
}

// TestScenario_RI_002_GetResourceServerInfoFailsClosed is OOS — see catalog out_of_scope_reason.
func TestScenario_RI_002_GetResourceServerInfoFailsClosed(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RI-002 (see catalog out_of_scope_reason)")
}

func TestScenario_RI_010_ResourceMustBeAbsoluteURI(t *testing.T) {
	t.Parallel()
	flow := runResourceAuthorizeError(t, "api")
	if flow.Error != "invalid_target" {
		t.Fatalf("error=%q want invalid_target", flow.Error)
	}
}

func TestScenario_RI_011_ResourceMustNotContainFragment(t *testing.T) {
	t.Parallel()
	flow := runResourceAuthorizeError(t, "https://api.example.com#frag")
	if flow.Error != "invalid_target" {
		t.Fatalf("error=%q want invalid_target", flow.Error)
	}
}

// TestScenario_RI_012_EachResourceValueValidatedIndividually is OOS — see catalog out_of_scope_reason.
func TestScenario_RI_012_EachResourceValueValidatedIndividually(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RI-012 (see catalog out_of_scope_reason)")
}

// TestScenario_RI_020_AuthorizeUnknownResourceFragmentRedirect is OOS — see catalog out_of_scope_reason.
func TestScenario_RI_020_AuthorizeUnknownResourceFragmentRedirect(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RI-020 (see catalog out_of_scope_reason)")
}

// TestScenario_RI_021_AuthorizeAllowedResourceBindsAudience verifies
// that requesting an allowed resource at /authorize lands as the
// access token's aud claim after a successful token exchange.
//
// Spec: RFC 8707 §3 (the AS MUST scope tokens to the requested
// resource; the conventional surface for that scoping is the JWT
// AT's aud claim).
func TestScenario_RI_021_AuthorizeAllowedResourceBindsAudience(t *testing.T) {
	t.Parallel()

	tk, rp, secret, callback := newResourceProvider(t)
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid profile",
		PKCE:        pkce,
		Extra: map[string][]string{
			"resource": {"https://api.example.com"},
		},
	})
	if flow.Error != "" {
		t.Fatalf("authorize error=%s desc=%s", flow.Error, flow.ErrorDesc)
	}
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: secret,
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	claims := decodeScenarioAccessTokenClaims(t, tok.AccessToken)
	if got := claims["aud"]; got != "https://api.example.com" {
		t.Fatalf("access_token aud=%v want https://api.example.com", got)
	}
}

// TestScenario_RI_022_AuthorizeAppliesDefaultResource is OOS — see catalog out_of_scope_reason.
func TestScenario_RI_022_AuthorizeAppliesDefaultResource(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RI-022 (see catalog out_of_scope_reason)")
}

// TestScenario_RI_023_AuthorizeGetAndPostBehaveIdentically verifies
// that resource validation behaves identically across GET /authorize
// (URL-encoded query) and POST /authorize (form-urlencoded body). An
// unknown resource MUST yield the same error envelope (302 redirect
// to the RP carrying error=invalid_target) on both methods.
//
// Spec: RFC 8707 §3 (resource validation is method-independent) /
// RFC 6749 §3.1 (the AS MUST support GET and MAY support POST at the
// authorization endpoint, with identical semantics).
func TestScenario_RI_023_AuthorizeGetAndPostBehaveIdentically(t *testing.T) {
	t.Parallel()

	tk, rp, _, callback := newResourceProvider(t)
	pkce := scenariokit.NewPKCEPair("")
	values := scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid profile",
		PKCE:        pkce,
		Extra: map[string][]string{
			"resource": {"https://api.unknown.example"},
		},
	}.Values()

	httpClient := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	getReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/auth?"+values.Encode(), http.NoBody)
	if err != nil {
		t.Fatalf("build GET /authorize: %v", err)
	}
	getResp, err := httpClient.Do(getReq)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = getResp.Body.Close() }()
	if getResp.StatusCode != http.StatusFound {
		t.Fatalf("GET /authorize status=%d want 302", getResp.StatusCode)
	}
	getLoc, err := getResp.Location()
	if err != nil {
		t.Fatalf("GET /authorize Location: %v", err)
	}

	postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/auth", strings.NewReader(values.Encode()))
	if err != nil {
		t.Fatalf("build POST /authorize: %v", err)
	}
	postReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	postResp, err := httpClient.Do(postReq)
	if err != nil {
		t.Fatalf("POST /authorize: %v", err)
	}
	defer func() { _ = postResp.Body.Close() }()
	if postResp.StatusCode != http.StatusFound {
		t.Fatalf("POST /authorize status=%d want 302", postResp.StatusCode)
	}
	postLoc, err := postResp.Location()
	if err != nil {
		t.Fatalf("POST /authorize Location: %v", err)
	}

	for _, want := range []struct {
		name string
		loc  *url.URL
	}{{"GET", getLoc}, {"POST", postLoc}} {
		if got := want.loc.Query().Get("error"); got != "invalid_target" {
			t.Errorf("%s error=%q want invalid_target (loc=%s)", want.name, got, want.loc.String())
		}
		if got := want.loc.Query().Get("state"); got != scenariokit.DefaultState {
			t.Errorf("%s state=%q want %q", want.name, got, scenariokit.DefaultState)
		}
		if want.loc.Fragment != "" || want.loc.RawFragment != "" {
			t.Errorf("%s response uses fragment encoding (got %q); code-flow MUST use query",
				want.name, want.loc.Fragment)
		}
	}
	if got, want := postLoc.Query().Get("error"), getLoc.Query().Get("error"); got != want {
		t.Errorf("POST error=%q != GET error=%q (parity violated)", got, want)
	}
}

// TestScenario_RI_030_AuthorizeCodeUnknownResourceQueryRedirect
// verifies that a response_type=code request asking for an unknown
// resource is rejected via a query-parameter redirect carrying
// error=invalid_target. Code-flow responses MUST use query encoding,
// never fragment encoding (RFC 6749 §4.1.2.1).
//
// Spec: RFC 8707 §3 (resource validation) / RFC 6749 §4.1.2.1
// (query-mode redirect for code flow).
func TestScenario_RI_030_AuthorizeCodeUnknownResourceQueryRedirect(t *testing.T) {
	t.Parallel()

	flow := runResourceAuthorizeError(t, "https://api.unknown.example")
	if flow.Error != "invalid_target" {
		t.Fatalf("error=%q want invalid_target", flow.Error)
	}
	if flow.Location == nil {
		t.Fatal("captured callback Location is nil")
	}
	if flow.Location.Fragment != "" || flow.Location.RawFragment != "" {
		t.Errorf("code-flow error redirect must not use fragment encoding, got fragment=%q",
			flow.Location.Fragment)
	}
	if flow.Location.RawQuery == "" {
		t.Error("code-flow error redirect must carry query parameters")
	}
	if flow.State != scenariokit.DefaultState {
		t.Errorf("state=%q want %q (state must be preserved across error redirects)",
			flow.State, scenariokit.DefaultState)
	}
}

// TestScenario_RI_031_AuthorizationCodePersistsResource verifies that
// an allowed `resource` parameter sent at /authorize is persisted on
// the authorization code record so the subsequent token exchange can
// scope tokens to the audience the user authorized.
//
// Spec: RFC 8707 §3 (the AS MUST remember the requested resource for
// the flow's full lifetime; the authorization-code record is the
// canonical place to persist it for the code grant).
func TestScenario_RI_031_AuthorizationCodePersistsResource(t *testing.T) {
	t.Parallel()

	tk, rp, _, callback := newResourceProvider(t)
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid profile",
		PKCE:        pkce,
		Extra: map[string][]string{
			"resource": {"https://api.example.com"},
		},
	})
	if flow.Error != "" {
		t.Fatalf("authorize error=%s desc=%s", flow.Error, flow.ErrorDesc)
	}
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	rec, err := tk.Store.AuthorizationCodes().Find(context.Background(), flow.Code)
	if err != nil {
		t.Fatalf("AuthorizationCodes.Find: %v", err)
	}
	if rec == nil {
		t.Fatal("authorization code record not found")
	}
	if got := rec.Resource; got != "https://api.example.com" {
		t.Errorf("authorization code resource=%q want %q", got, "https://api.example.com")
	}
}

func TestScenario_RI_032_TokenExchangePropagatesCodeResource(t *testing.T) {
	t.Parallel()
	tk, rp, secret, callback := newResourceProvider(t)
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid profile offline_access",
		PKCE:        pkce,
		Extra: map[string][]string{
			"resource": {"https://api.example.com"},
		},
	})
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: secret,
	})
	if tok.StatusCode != 200 {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	claims := decodeScenarioAccessTokenClaims(t, tok.AccessToken)
	if got := claims["aud"]; got != "https://api.example.com" {
		t.Fatalf("aud=%v want https://api.example.com", got)
	}
	rec, err := tk.Store.RefreshTokens().Find(context.Background(), tok.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshTokens.Find: %v", err)
	}
	if rec.Resource != "https://api.example.com" {
		t.Fatalf("refresh resource=%q want https://api.example.com", rec.Resource)
	}
}

func TestScenario_RI_033_RefreshPreservesResource(t *testing.T) {
	t.Parallel()
	tk, rp, secret, callback := newResourceProvider(t)
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid profile offline_access",
		PKCE:        pkce,
		Extra: map[string][]string{
			"resource": {"https://api.example.com"},
		},
	})
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: secret,
	})
	refreshed := refreshScenarioToken(t, tk, tok.RefreshToken, rp.ID, secret)
	if refreshed.StatusCode != 200 {
		t.Fatalf("/token refresh status=%d body=%v", refreshed.StatusCode, refreshed.Raw)
	}
	claims := decodeScenarioAccessTokenClaims(t, refreshed.AccessToken)
	if got := claims["aud"]; got != "https://api.example.com" {
		t.Fatalf("aud=%v want https://api.example.com", got)
	}
	rec, err := tk.Store.RefreshTokens().Find(context.Background(), refreshed.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshTokens.Find: %v", err)
	}
	if rec.Resource != "https://api.example.com" {
		t.Fatalf("refresh resource=%q want https://api.example.com", rec.Resource)
	}
}

// TestScenario_RI_034_DefaultResourceFlowsToCodeAndTokens is OOS — see catalog out_of_scope_reason.
func TestScenario_RI_034_DefaultResourceFlowsToCodeAndTokens(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RI-034 (see catalog out_of_scope_reason)")
}

func TestScenario_RI_035_UseGrantedResourceHookAtTokenExchange(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-035")
}

func TestScenario_RI_036_TokenExchangeAcceptsExplicitResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-036")
}

// TestScenario_RI_040_DeviceAuthRejectsUnknownResource is OOS — see catalog out_of_scope_reason.
func TestScenario_RI_040_DeviceAuthRejectsUnknownResource(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RI-040 (see catalog out_of_scope_reason)")
}

// TestScenario_RI_041_DeviceTokenBindsAudienceAndResource is OOS — see catalog out_of_scope_reason.
func TestScenario_RI_041_DeviceTokenBindsAudienceAndResource(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RI-041 (see catalog out_of_scope_reason)")
}

func TestScenario_RI_042_DeviceFlowDefaultResourceAndRefresh(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-042")
}

func TestScenario_RI_043_DeviceFlowUseGrantedResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-043")
}

func TestScenario_RI_044_DeviceFlowExplicitResourceAtExchange(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-044")
}

// TestScenario_RI_050_BackchannelRejectsUnknownResource is OOS — see catalog out_of_scope_reason.
func TestScenario_RI_050_BackchannelRejectsUnknownResource(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RI-050 (see catalog out_of_scope_reason)")
}

// TestScenario_RI_051_CIBATokenBindsAudienceAndResource is OOS — see catalog out_of_scope_reason.
func TestScenario_RI_051_CIBATokenBindsAudienceAndResource(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RI-051 (see catalog out_of_scope_reason)")
}

func TestScenario_RI_052_CIBARefreshPreservesResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-052")
}

func TestScenario_RI_053_CIBADefaultResourceWithUseGrantedResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-053")
}

// TestScenario_RI_054_CIBAUseGrantedResourceFalseLeavesAudienceUnset is OOS — see catalog out_of_scope_reason.
func TestScenario_RI_054_CIBAUseGrantedResourceFalseLeavesAudienceUnset(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RI-054 (see catalog out_of_scope_reason)")
}

// TestScenario_RI_060_ClientCredentialsBindsAudience verifies the
// RFC 8707 §3 contract on the client_credentials grant: a request
// carrying an explicit, allowlisted resource indicator MUST yield an
// access token whose "aud" equals that resource. The fall-back to the
// issuer audience covers the absent-resource path; this scenario
// exercises the bound-audience path.
//
// Spec: RFC 8707 §3.
func TestScenario_RI_060_ClientCredentialsBindsAudience(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-ri-060"
		callback = "https://rp.testkit.invalid/callback"
		resource = "https://api.example.com"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ri-060-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"read"},
		Resources:               []string{resource},
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"read"},
		"resource":   {resource},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode /token body: %v", err)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatalf("access_token missing on success path: %v", body)
	}
	claims := decodeScenarioAccessTokenClaims(t, at)
	if got := claims["aud"]; got != resource {
		t.Fatalf("access_token aud=%v want %q", got, resource)
	}
}

// TestScenario_RI_061_ClientCredentialsDropsUnsupportedScopes is OOS — see catalog out_of_scope_reason.
func TestScenario_RI_061_ClientCredentialsDropsUnsupportedScopes(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RI-061 (see catalog out_of_scope_reason)")
}

// TestScenario_RI_062_ClientCredentialsRejectsUnknownResource verifies
// that a grant_type=client_credentials request whose `resource`
// parameter is not on the client's [store.Client.Resources] allowlist
// is rejected with 400 invalid_target. The wire description matches
// the /authorize-side `ErrResourceNotAllowed` posture so a client that
// ports a request between endpoints sees a uniform error envelope.
//
// Spec: RFC 8707 §3 (the AS MUST refuse a token request whose resource
// indicator is not authorised for the client) / RFC 6749 §5.2.
func TestScenario_RI_062_ClientCredentialsRejectsUnknownResource(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-ri-062"
		callback = "https://rp.testkit.invalid/callback"
		allowed  = "https://api.example.com"
		unknown  = "https://api.unknown.example"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ri-062-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"read"},
		Resources:               []string{allowed},
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"read"},
		"resource":   {unknown},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode /token body: %v", err)
	}
	if got, _ := body["error"].(string); got != "invalid_target" {
		t.Fatalf("error=%q want invalid_target (body=%v)", got, body)
	}
	if got, _ := body["error_description"].(string); got != "resource indicator is missing, or unknown" {
		t.Errorf("error_description=%q want \"resource indicator is missing, or unknown\"", got)
	}
}

// TestScenario_RI_063_ClientCredentialsRejectsMultipleResources verifies
// the v1.0 single-valued posture for the `resource` parameter on the
// client_credentials grant: when the request body carries two
// different `resource` values, the OP MUST reject with 400
// invalid_target and the description "only a single resource indicator
// value is supported". Repeated *identical* values are tolerated (the
// duplicate-tolerance posture mirrors the /authorize side's
// `singleValue` parser; see internal/tokenendpoint/clientcred.go's
// parseClientCredsRequest godoc).
//
// Spec: RFC 8707 §2 (the AS MAY restrict the resource parameter to a
// single value per profile) / RFC 6749 §5.2.
func TestScenario_RI_063_ClientCredentialsRejectsMultipleResources(t *testing.T) {
	t.Parallel()

	const (
		clientID  = "rp-ri-063"
		callback  = "https://rp.testkit.invalid/callback"
		resourceA = "https://api.a.example"
		resourceB = "https://api.b.example"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-ri-063-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"read"},
		Resources:               []string{resourceA, resourceB},
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	form := url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"read"},
		"resource":   {resourceA, resourceB},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode /token body: %v", err)
	}
	if got, _ := body["error"].(string); got != "invalid_target" {
		t.Fatalf("error=%q want invalid_target (body=%v)", got, body)
	}
	if got, _ := body["error_description"].(string); got != "only a single resource indicator value is supported" {
		t.Errorf("error_description=%q want \"only a single resource indicator value is supported\"", got)
	}
}

// TestScenario_RI_064_ClientCredentialsValidatesEachResource is OOS — see catalog out_of_scope_reason.
func TestScenario_RI_064_ClientCredentialsValidatesEachResource(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RI-064 (see catalog out_of_scope_reason)")
}

func TestScenario_RI_065_ClientCredentialsAppliesDefaultResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-065")
}

func TestScenario_RI_066_ResourceTokenFormatPolicy(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-066")
}

func TestScenario_RI_070_UserInfoAcceptsAudienceLessTokens(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-070")
}

// TestScenario_RI_071_UserInfoRejectsResourceBoundTokens verifies that
// an access token whose "aud" claim names a resource server (i.e. the
// RFC 8707 §2.1 path where the RP requested resource=<URI>) cannot be
// presented at /userinfo. The OP enforces aud-contains-issuer at the
// userinfo handler so that a token minted for an external resource
// cannot read end-user claims even though it shares the OP's signing
// key.
//
// The wire shape diverges from panva's panva-residue framing: v1.0
// emits the bare RFC 6750 §3.1 invalid_token challenge with no
// "error_detail" extension. The privacy posture (do not name the
// sub-cause) matches every other userinfo failure path.
//
// Spec: OIDC Core §5.3 + RFC 8707 §3 / RFC 6750 §3.1.
func TestScenario_RI_071_UserInfoRejectsResourceBoundTokens(t *testing.T) {
	t.Parallel()

	tk, rp, secret, callback := newResourceProvider(t)
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid profile",
		PKCE:        pkce,
		Extra: map[string][]string{
			"resource": {"https://api.example.com"},
		},
	})
	if flow.Error != "" {
		t.Fatalf("authorize error=%s desc=%s", flow.Error, flow.ErrorDesc)
	}
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:         flow.Code,
		RedirectURI:  callback,
		Verifier:     pkce.Verifier,
		ClientID:     rp.ID,
		ClientSecret: secret,
	})
	if tok.StatusCode != http.StatusOK || tok.AccessToken == "" {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	claims := decodeScenarioAccessTokenClaims(t, tok.AccessToken)
	if got := claims["aud"]; got != "https://api.example.com" {
		t.Fatalf("precondition: access_token aud=%v want https://api.example.com", got)
	}

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/oidc/userinfo", http.NoBody)
	if err != nil {
		t.Fatalf("build /userinfo request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok.AccessToken)

	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /userinfo: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, body)
	}
	chall := resp.Header.Get("WWW-Authenticate")
	if !strings.HasPrefix(chall, "Bearer ") {
		t.Errorf("WWW-Authenticate=%q want Bearer challenge", chall)
	}
	if !strings.Contains(chall, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate=%q missing error=invalid_token", chall)
	}
}

// TestScenario_RI_072_UserInfoRejectsNonStringAudience is OOS — see catalog out_of_scope_reason.
func TestScenario_RI_072_UserInfoRejectsNonStringAudience(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: RI-072 (see catalog out_of_scope_reason)")
}

func newResourceProvider(t *testing.T) (*testkit.Provider, *store.Client, string, string) {
	t.Helper()

	const (
		clientID     = "rp-ri"
		clientSecret = "rp-ri-secret"
		callback     = "https://rp.testkit.invalid/callback"
	)
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
		Resources:               []string{"https://api.example.com"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	return tk, rp, clientSecret, callback
}

func runResourceAuthorizeError(t *testing.T, resource string) scenariokit.CodeFlowResult {
	t.Helper()

	tk, rp, _, callback := newResourceProvider(t)
	return scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		Scope:       "openid profile",
		PKCE:        scenariokit.NewPKCEPair(""),
		Extra: map[string][]string{
			"resource": {resource},
		},
	})
}

func decodeScenarioAccessTokenClaims(t *testing.T, accessToken string) map[string]any {
	t.Helper()

	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		t.Fatalf("jwt has %d parts, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}

func refreshScenarioToken(t *testing.T, tk *testkit.Provider, refreshToken, clientID, clientSecret string) scenariokit.TokenResponse {
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
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /token refresh: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var raw map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		t.Fatalf("decode refresh body: %v", err)
	}
	out := scenariokit.TokenResponse{StatusCode: resp.StatusCode, Raw: raw}
	out.AccessToken, _ = raw["access_token"].(string)
	out.RefreshToken, _ = raw["refresh_token"].(string)
	out.IDToken, _ = raw["id_token"].(string)
	return out
}
