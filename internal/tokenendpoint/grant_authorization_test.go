package tokenendpoint_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// Two independent gates decide whether a /token request may run a
// grant: the Provider's configured grant set (which is what discovery
// advertises) and the authenticated client's own registration. Both run
// before any credential record is read or consumed, so a refused
// request leaves the code / refresh chain exactly as it found it —
// otherwise narrowing a compromised client's registration would still
// let its outstanding credentials be spent once each.

// registerGrantScopedClient seeds a confidential client with an explicit
// GrantTypes list.
func registerGrantScopedClient(tb testing.TB, f *fixture, id string, grantTypes []string) (*store.Client, string) {
	tb.Helper()
	const secret = "grant-gate-secret" //nolint:gosec // G101: test fixture, not a real credential.
	hash, err := (&clientauth.Argon2id{}).Hash(secret)
	if err != nil {
		tb.Fatalf("Argon2id.Hash: %v", err)
	}
	client := f.prov.RegisterClient(tb, testkit.ClientFixture{
		ID:                      id,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              grantTypes,
		Scopes:                  []string{"openid", "profile"},
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
	})
	return client, secret
}

// TestTokenGrantGate_AuthorizationCodeNotRegistered asserts a client
// without authorization_code in its registration cannot exchange a code,
// and — the part that matters operationally — that the refused exchange
// does not consume the code. A gate that ran after the exchange would
// still burn every outstanding code of a client the operator has just
// locked down.
func TestTokenGrantGate_AuthorizationCodeNotRegistered(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := registerGrantScopedClient(t, f, "client-no-authcode", []string{"refresh_token"})
	verifier, challenge := pkcePair()

	const code = "code-grant-gate"
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  code,
		ClientID:            client.ID,
		Subject:             "user-grant-gate",
		RedirectURI:         client.RedirectURIs[0],
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	resp := f.post(t, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {client.RedirectURIs[0]},
		"code_verifier": {verifier},
	}, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	if got := decodeJSON(t, resp)["error"]; got != "unauthorized_client" {
		t.Errorf("error=%v want unauthorized_client", got)
	}

	stored, err := f.prov.Store.AuthorizationCodes().Find(context.Background(), code)
	if err != nil {
		t.Fatalf("the refused exchange consumed or removed the code: %v", err)
	}
	if stored.ConsumedAt != nil {
		t.Errorf("code ConsumedAt=%v; a refused exchange must not consume the code", stored.ConsumedAt)
	}
}

// TestTokenGrantGate_RefreshTokenNotRegistered is the rotation half: a
// client that lost refresh_token cannot rotate, and the presented token
// survives unconsumed with no successor minted.
func TestTokenGrantGate_RefreshTokenNotRegistered(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := registerGrantScopedClient(t, f, "client-no-refresh", []string{"authorization_code"})

	const refreshID = "rt-grant-gate"
	f.seedGrant(t, &store.Grant{
		ID:       "grant-grant-gate",
		Subject:  "user-grant-gate",
		ClientID: client.ID,
		Scope:    []string{"openid"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       refreshID,
		ClientID: client.ID,
		Subject:  "user-grant-gate",
		GrantID:  "grant-grant-gate",
		Scope:    []string{"openid"},
	})

	resp := f.post(t, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshID},
	}, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	if got := decodeJSON(t, resp)["error"]; got != "unauthorized_client" {
		t.Errorf("error=%v want unauthorized_client", got)
	}

	stored, err := f.prov.Store.RefreshTokens().Find(context.Background(), refreshID)
	if err != nil {
		t.Fatalf("the refused rotation consumed or removed the refresh token: %v", err)
	}
	if stored.ConsumedAt != nil {
		t.Errorf("refresh token ConsumedAt=%v; a refused rotation must not consume it", stored.ConsumedAt)
	}
}

// TestTokenGrantGate_ProviderGrantSet asserts the Provider-level gate:
// a grant left out of op.WithGrants is refused with
// unsupported_grant_type, and the discovery document advertises exactly
// the set the endpoint accepts. Advertising a grant the endpoint
// refuses (or accepting one it never advertised) is the drift the two
// gates share a projection to prevent.
func TestTokenGrantGate_ProviderGrantSet(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithGrants(grant.AuthorizationCode)),
	)
	f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/token", clock: clock}

	// The client is registered for client_credentials, so only the
	// Provider-level gate can refuse the request.
	client, secret := registerGrantScopedClient(t, f, "client-cc-not-enabled",
		[]string{"authorization_code", "client_credentials"})

	resp := f.post(t, url.Values{
		"grant_type": {"client_credentials"},
		"scope":      {"profile"},
	}, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	if got := decodeJSON(t, resp)["error"]; got != "unsupported_grant_type" {
		t.Errorf("error=%v want unsupported_grant_type", got)
	}

	advertised := discoveryGrantTypes(t, prov)
	want := []string{"authorization_code"}
	if len(advertised) != len(want) || advertised[0] != want[0] {
		t.Errorf("discovery grant_types_supported=%v want %v (the advertised set must equal the accepted set)",
			advertised, want)
	}
}

// discoveryGrantTypes reads grant_types_supported off the provider's
// discovery document.
func discoveryGrantTypes(tb testing.TB, prov *testkit.Provider) []string {
	tb.Helper()
	req, err := http.NewRequestWithContext(tb.Context(), http.MethodGet,
		prov.Server.URL+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		tb.Fatalf("build discovery request: %v", err)
	}
	resp, err := prov.HTTPClient(nil).Do(req)
	if err != nil {
		tb.Fatalf("GET discovery: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("read discovery: %v", err)
	}
	var doc struct {
		GrantTypesSupported []string `json:"grant_types_supported"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		tb.Fatalf("decode discovery: %v", err)
	}
	return doc.GrantTypesSupported
}
