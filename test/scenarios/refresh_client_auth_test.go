package scenarios_test

// Spec: RFC 6749 §5.2 (client authentication) / §6 (refreshing a token).

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// issueRefreshTokenForConfidentialClient registers a client_secret_basic
// confidential client, drives a full code flow requesting offline_access,
// and returns the provider, the client's secret, and the resulting refresh
// token. The refresh token is known-valid, so any subsequent rejection in
// a caller's malformed-auth follow-up request is attributable only to that
// request's client authentication.
func issueRefreshTokenForConfidentialClient(t *testing.T, clientID string) (*testkit.Provider, string, string) {
	t.Helper()
	const callback = "https://rp.testkit.invalid/callback"
	clientSecret := clientID + "-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithStrictOfflineAccess()))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "offline_access"},
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
		t.Fatalf("code exchange did not yield a refresh token: status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	return tk, clientSecret, tok.RefreshToken
}

// TestRefreshTokenGrantRejectsMissingClientAuthentication pins that a
// refresh_token grant from a confidential client, presented with no
// client authentication at all (no Authorization header, no body
// client_id/client_secret), is rejected as invalid_client rather than
// treated as an unauthenticated bare refresh.
//
// Tracks: CVE-2026-53512 — a refresh_token grant was accepted with no
// client authentication at all, letting possession of the refresh
// token alone stand in for the confidential client's credential.
// Sibling tests in this file pin the wrong-secret and none-auth
// variants of the same gate.
func TestRefreshTokenGrantRejectsMissingClientAuthentication(t *testing.T) {
	t.Parallel()
	const clientID = "ca-refresh-noauth"
	tk, _, refreshToken := issueRefreshTokenForConfidentialClient(t, clientID)

	resp := postTokenForm(t, tk, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}, nil)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_client" {
		t.Errorf("error=%q want invalid_client (body=%v)", got, resp.Body)
	}
}

// TestRefreshTokenGrantRejectsWrongClientSecret pins that a refresh_token
// grant carrying the right client_id but the wrong client_secret over
// Basic auth is rejected as invalid_client rather than silently
// authenticated because the refresh_token itself is valid.
func TestRefreshTokenGrantRejectsWrongClientSecret(t *testing.T) {
	t.Parallel()
	const clientID = "ca-refresh-wrongsecret"
	tk, _, refreshToken := issueRefreshTokenForConfidentialClient(t, clientID)

	resp := postTokenForm(t, tk, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}, func(r *http.Request) {
		r.SetBasicAuth(clientID, "definitely-not-the-secret")
	})

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_client" {
		t.Errorf("error=%q want invalid_client (body=%v)", got, resp.Body)
	}
}

// TestRefreshTokenGrantRejectsNoneAuthForConfidentialClient pins that a
// refresh_token grant presenting only client_id in the body — the "none"
// authentication method — is rejected for a confidential client, even
// though the shape would authenticate a public client and the
// refresh_token itself is valid.
func TestRefreshTokenGrantRejectsNoneAuthForConfidentialClient(t *testing.T) {
	t.Parallel()
	const clientID = "ca-refresh-none"
	tk, _, refreshToken := issueRefreshTokenForConfidentialClient(t, clientID)

	resp := postTokenForm(t, tk, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
	}, nil)

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", resp.StatusCode, resp.Body)
	}
	if got, _ := resp.Body["error"].(string); got != "invalid_client" {
		t.Errorf("error=%q want invalid_client (body=%v)", got, resp.Body)
	}
}
