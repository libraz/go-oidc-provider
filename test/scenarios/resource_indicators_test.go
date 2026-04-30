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

func TestScenario_RI_002_GetResourceServerInfoFailsClosed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-002")
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

func TestScenario_RI_012_EachResourceValueValidatedIndividually(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-012")
}

func TestScenario_RI_020_AuthorizeUnknownResourceFragmentRedirect(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-020")
}

func TestScenario_RI_021_AuthorizeAllowedResourceBindsAudience(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-021")
}

func TestScenario_RI_022_AuthorizeAppliesDefaultResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-022")
}

func TestScenario_RI_023_AuthorizeGetAndPostBehaveIdentically(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-023")
}

func TestScenario_RI_030_AuthorizeCodeUnknownResourceQueryRedirect(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-030")
}

func TestScenario_RI_031_AuthorizationCodePersistsResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-031")
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

func TestScenario_RI_034_DefaultResourceFlowsToCodeAndTokens(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-034")
}

func TestScenario_RI_035_UseGrantedResourceHookAtTokenExchange(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-035")
}

func TestScenario_RI_036_TokenExchangeAcceptsExplicitResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-036")
}

func TestScenario_RI_040_DeviceAuthRejectsUnknownResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-040")
}

func TestScenario_RI_041_DeviceTokenBindsAudienceAndResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-041")
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

func TestScenario_RI_050_BackchannelRejectsUnknownResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-050")
}

func TestScenario_RI_051_CIBATokenBindsAudienceAndResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-051")
}

func TestScenario_RI_052_CIBARefreshPreservesResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-052")
}

func TestScenario_RI_053_CIBADefaultResourceWithUseGrantedResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-053")
}

func TestScenario_RI_054_CIBAUseGrantedResourceFalseLeavesAudienceUnset(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-054")
}

func TestScenario_RI_060_ClientCredentialsBindsAudience(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-060")
}

func TestScenario_RI_061_ClientCredentialsDropsUnsupportedScopes(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-061")
}

func TestScenario_RI_062_ClientCredentialsRejectsUnknownResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-062")
}

func TestScenario_RI_063_ClientCredentialsRejectsMultipleResources(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-063")
}

func TestScenario_RI_064_ClientCredentialsValidatesEachResource(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-064")
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

func TestScenario_RI_071_UserInfoRejectsResourceBoundTokens(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-071")
}

func TestScenario_RI_072_UserInfoRejectsNonStringAudience(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RI-072")
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
