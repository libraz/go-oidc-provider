package tokenendpoint_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
)

// seedPlainOAuthCode seeds a grant plus authorization code whose scope
// deliberately omits "openid", i.e. the plain OAuth 2.0 shape a
// deployment running with op.WithOpenIDScopeOptional serves. Returns the
// PKCE verifier and the redirect URI the caller replays at /token.
func seedPlainOAuthCode(tb testing.TB, f *fixture, client *store.Client, codeID, grantID string) (verifier, redirect string) {
	tb.Helper()
	verifier, challenge := pkcePair()
	redirect = client.RedirectURIs[0]
	f.seedGrant(tb, &store.Grant{
		ID: grantID, Subject: "user-1", ClientID: client.ID,
		Scope: []string{"api:read"},
	})
	f.seedAuthCode(tb, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             "user-1",
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"api:read"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	return verifier, redirect
}

// TestOpenIDScopeOptional_AuthCodeIssuesRefreshWithoutOpenID pins the
// refresh half of op.WithOpenIDScopeOptional. The option's contract is
// that a request omitting "openid" runs as plain OAuth 2.0
// authorization_code with an access token and an optional refresh
// token; a gate that still demanded "openid" would withhold refresh
// tokens from exactly the non-OIDC clients the option exists to serve,
// while custom grants (which never consult the gate) kept receiving
// them. The response must stay free of an id_token: relaxing the scope
// requirement does not turn a plain OAuth exchange into an OIDC one.
func TestOpenIDScopeOptional_AuthCodeIssuesRefreshWithoutOpenID(t *testing.T) {
	t.Parallel()

	f := newFixtureWithOptions(t, op.WithOpenIDScopeOptional())
	client, secret := f.confidentialClientFixture(t)
	verifier, redirect := seedPlainOAuthCode(t, f, client, "code-plain-oauth", "grant-plain-oauth")

	resp := f.post(t, authCodeForm("code-plain-oauth", redirect, verifier), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["scope"]; got != "api:read" {
		t.Errorf("scope=%v want api:read", got)
	}
	if _, ok := body["id_token"]; ok {
		t.Errorf("id_token must be absent for a scope without openid: %v", body)
	}
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("refresh_token must be issued under WithOpenIDScopeOptional: %v", body)
	}
	rec, err := f.prov.Store.RefreshTokens().Find(context.Background(), rt)
	if err != nil || rec == nil {
		t.Fatalf("RefreshTokens.Find(%q): rec=%v err=%v", rt, rec, err)
	}
	if len(rec.Scope) != 1 || rec.Scope[0] != "api:read" {
		t.Errorf("persisted refresh scope=%v want [api:read]", rec.Scope)
	}
}

// TestOpenIDScopeOptional_RefreshExchangeRotatesPlainOAuthChain follows
// the issued token through one rotation: a plain OAuth chain must keep
// refreshing, otherwise the first exchange hands the client a token it
// can never use.
func TestOpenIDScopeOptional_RefreshExchangeRotatesPlainOAuthChain(t *testing.T) {
	t.Parallel()

	f := newFixtureWithOptions(t, op.WithOpenIDScopeOptional())
	client, secret := f.confidentialClientFixture(t)
	const tokenID = "rt-plain-oauth" //nolint:gosec // opaque test fixture id, not a credential.
	f.seedGrant(t, &store.Grant{
		ID: "grant-plain-oauth-refresh", Subject: "user-1", ClientID: client.ID,
		Scope: []string{"api:read"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-plain-oauth-refresh",
		Scope:    []string{"api:read"},
	})

	resp := f.post(t, refreshForm(tokenID, ""), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	if rotated, _ := decodeJSON(t, resp)["refresh_token"].(string); rotated == "" {
		t.Error("refresh_token must rotate for a plain OAuth chain")
	}
}

// TestOpenIDScopeOptional_AbsentWithholdsRefreshWithoutOpenID is the
// regression guard on the default posture. Without the option the OP is
// a strict OIDC OP, so a granted scope lacking "openid" receives no
// refresh token — the historical behaviour must not shift as a side
// effect of the option becoming effective.
func TestOpenIDScopeOptional_AbsentWithholdsRefreshWithoutOpenID(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	verifier, redirect := seedPlainOAuthCode(t, f, client, "code-no-openid", "grant-no-openid")

	resp := f.post(t, authCodeForm("code-no-openid", redirect, verifier), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	if body := decodeJSON(t, resp); body["refresh_token"] != nil {
		t.Errorf("refresh_token must be absent without WithOpenIDScopeOptional: %v", body)
	}
}
