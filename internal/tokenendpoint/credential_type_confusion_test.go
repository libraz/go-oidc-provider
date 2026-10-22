package tokenendpoint_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
)

// issueUserAccessToken rotates a seeded refresh token for the fixture's
// confidential client and returns the access token the OP issued with
// the client and its secret.
func issueUserAccessToken(tb testing.TB, f *fixture, seed, grantID string) (at string, client *store.Client, secret string) {
	tb.Helper()
	client, secret = f.confidentialClientFixture(tb)
	scope := []string{"openid", "offline_access"}
	f.seedGrant(tb, &store.Grant{ID: grantID, Subject: "user-1", ClientID: client.ID, Scope: scope})
	f.seedRefreshToken(tb, &store.RefreshToken{
		ID: seed, ClientID: client.ID, Subject: "user-1", GrantID: grantID, Scope: scope,
	})
	resp := f.post(tb, refreshForm(seed, ""), client.ID, secret)
	defer resp.Body.Close()
	body := decodeJSON(tb, resp)
	at, _ = body["access_token"].(string)
	if resp.StatusCode != http.StatusOK || at == "" {
		tb.Fatalf("seed rotation status=%d body=%v", resp.StatusCode, body)
	}
	return at, client, secret
}

// TestClientCredentials_BearerAccessTokenIsNotClientAuthentication pins
// that a valid user access token presented as a Bearer credential on a
// client_credentials request does not stand in for the client secret:
// the request is refused invalid_client and nothing is issued.
//
// Tracks: CVE-2026-59358 (Cloud Foundry UAA — a user access token presented as Bearer on client_credentials was accepted in place of the client secret)
func TestClientCredentials_BearerAccessTokenIsNotClientAuthentication(t *testing.T) {
	t.Parallel()

	for name, format := range map[string]op.AccessTokenFormat{
		"jwt":    op.AccessTokenFormatJWT,
		"opaque": op.AccessTokenFormatOpaque,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newClientCredsFixture(t, op.WithAccessTokenFormat(format))
			userAT, _, _ := issueUserAccessToken(t, f, "rt-bearer-"+name, "grant-bearer-"+name)
			client, _ := clientCredsClient(t, f.prov, []string{"read"})

			form := url.Values{}
			form.Set("grant_type", "client_credentials")
			form.Set("client_id", client.ID)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.endpoint, strings.NewReader(form.Encode()))
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Authorization", "Bearer "+userAT)
			resp, err := f.prov.HTTPClient(nil).Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()

			assertOAuthError(t, resp, http.StatusUnauthorized, "invalid_client")
		})
	}
}

// TestRefreshGrant_AccessTokenPresentedAsRefreshTokenRefused pins that
// the refresh grant resolves its credential as a refresh token only: a
// valid access token (either format) in the refresh_token parameter is
// invalid_grant and mints nothing.
//
// Tracks: CVE-2026-101023 (Gitea — the refresh grant checked signature and grant but not token type, so an access token redeemed as a refresh token)
func TestRefreshGrant_AccessTokenPresentedAsRefreshTokenRefused(t *testing.T) {
	t.Parallel()

	for name, format := range map[string]op.AccessTokenFormat{
		"jwt":    op.AccessTokenFormatJWT,
		"opaque": op.AccessTokenFormatOpaque,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newFixtureWithOptions(t, op.WithAccessTokenFormat(format))
			at, client, secret := issueUserAccessToken(t, f, "rt-type-"+name, "grant-type-"+name)

			resp := f.post(t, refreshForm(at, ""), client.ID, secret)
			defer resp.Body.Close()
			body := decodeJSON(t, resp)
			if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
				t.Fatalf("status=%d body=%v, want 400 invalid_grant", resp.StatusCode, body)
			}
			for _, k := range []string{"access_token", "refresh_token", "id_token"} {
				if _, ok := body[k]; ok {
					t.Errorf("refusal carried %s", k)
				}
			}
		})
	}
}
