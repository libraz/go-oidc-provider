package scenarios_test

// Spec: RFC 8707 — Resource Indicators for OAuth 2.0, §2.2.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// TestRefreshTokenIgnoresRequestSuppliedResource pins that a refresh
// request cannot switch or widen the access token audience by supplying
// its own "resource" parameter. parseRefreshRequest
// (internal/tokenendpoint/refresh.go) never reads a resource form value in
// the first place, so both the issued access token's audience and the
// refresh token's own recorded resource must stay exactly the grant's
// original resource, regardless of what the request asks for.
//
// Tracks: CVE-2026-86073 — an RFC 8707 resource indicator supplied on a
// refresh request substituted the token's audience for one the
// authorization grant never approved.
func TestRefreshTokenIgnoresRequestSuppliedResource(t *testing.T) {
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
	if tok.StatusCode != http.StatusOK || tok.RefreshToken == "" {
		t.Fatalf("code exchange did not yield a refresh token: status=%d body=%v", tok.StatusCode, tok.Raw)
	}

	refreshed := refreshScenarioTokenWithResource(t, tk, tok.RefreshToken, rp.ID, secret, "https://attacker.example.com")
	if refreshed.StatusCode != http.StatusOK {
		t.Fatalf("/token refresh status=%d body=%v", refreshed.StatusCode, refreshed.Raw)
	}

	claims := decodeScenarioAccessTokenClaims(t, refreshed.AccessToken)
	if got := claims["aud"]; got != "https://api.example.com" {
		t.Fatalf("aud=%v want https://api.example.com (request-supplied resource must be ignored)", got)
	}
	rec, err := tk.Store.RefreshTokens().Find(context.Background(), refreshed.RefreshToken)
	if err != nil {
		t.Fatalf("RefreshTokens.Find: %v", err)
	}
	if rec.Resource != "https://api.example.com" {
		t.Fatalf("refresh resource=%q want https://api.example.com (grant's resource must not change)", rec.Resource)
	}
}

// refreshScenarioTokenWithResource is refreshScenarioToken
// (resource_indicators_test.go) plus a request-supplied "resource" form
// value, needed here to prove the value has no effect.
func refreshScenarioTokenWithResource(t *testing.T, tk *testkit.Provider, refreshToken, clientID, clientSecret, resource string) scenariokit.TokenResponse {
	t.Helper()

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"resource":      {resource},
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
