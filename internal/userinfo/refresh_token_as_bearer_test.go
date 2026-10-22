package userinfo_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
)

// TestHandler_RefreshTokenAsBearerRefused presents a live refresh token
// value as the Bearer credential and requires 401 invalid_token with no
// claims, under both access-token formats: the bearer lookup resolves
// access tokens only and never falls through to the refresh substore.
//
// Tracks: CVE-2025-7043 (ForgeRock — a refresh token was accepted as an access token at the userinfo endpoint)
func TestHandler_RefreshTokenAsBearerRefused(t *testing.T) {
	t.Parallel()

	for name, format := range map[string]op.AccessTokenFormat{
		"jwt":    op.AccessTokenFormatJWT,
		"opaque": op.AccessTokenFormatOpaque,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newUserInfoFixtureWithOptions(t, op.WithAccessTokenFormat(format))
			const subject = "user-refresh-as-bearer"
			f.putUser(t, subject, map[string]any{"email": "victim@example.com"})
			const grantID = "grant-refresh-as-bearer"
			if err := f.prov.Store.Grants().Save(context.Background(), &store.Grant{
				ID: grantID, Subject: subject, ClientID: fixtureClientID,
				Scope:     []string{"openid", "email", "offline_access"},
				CreatedAt: f.clock.now, UpdatedAt: f.clock.now,
			}); err != nil {
				t.Fatalf("Grants.Save: %v", err)
			}
			rt := &store.RefreshToken{
				ID: "rt-refresh-as-bearer", ClientID: fixtureClientID, Subject: subject, GrantID: grantID,
				Scope:     []string{"openid", "email", "offline_access"},
				CreatedAt: f.clock.now, ExpiresAt: f.clock.now.Add(time.Hour),
			}
			if err := f.prov.Store.RefreshTokens().Save(context.Background(), rt); err != nil {
				t.Fatalf("RefreshTokens.Save: %v", err)
			}

			resp := f.doRequest(t, f.newGet(t, rt.ID))
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status=%d want 401", resp.StatusCode)
			}
			if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, `error="invalid_token"`) {
				t.Fatalf("WWW-Authenticate=%q want invalid_token", got)
			}
			assertNoClaimLeak(t, resp)
		})
	}
}
