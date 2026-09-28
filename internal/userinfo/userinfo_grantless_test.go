package userinfo_test

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
)

// TestHandler_ClientCredentialsTokenRejected pins that a token with no
// grant lineage — the shape client_credentials mints, "sub" set to the
// client_id — is refused in every subject configuration and format,
// even when a user record happens to share that subject value.
func TestHandler_ClientCredentialsTokenRejected(t *testing.T) {
	t.Parallel()

	configs := []struct {
		name string
		opts []op.Option
	}{
		{name: "public subjects"},
		{name: "pairwise subjects", opts: []op.Option{op.WithPairwiseSubject([]byte("userinfo-grantless-salt-32-bytes!"))}},
	}
	formats := []struct {
		name  string
		token func(t *testing.T, f *userInfoFixture) string
	}{
		{
			name: "jwt",
			token: func(t *testing.T, f *userInfoFixture) string {
				t.Helper()
				return f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
					c.Subject = fixtureClientID
					c.GrantID = ""
				})
			},
		},
		{
			name: "opaque",
			token: func(t *testing.T, f *userInfoFixture) string {
				t.Helper()
				rec := &store.OpaqueAccessToken{
					ID:        "opaque-client-credentials",
					ClientID:  fixtureClientID,
					Subject:   fixtureClientID,
					Scope:     []string{"openid", "email"},
					IssuedAt:  f.clock.now,
					ExpiresAt: f.clock.now.Add(time.Hour),
				}
				f.saveOpaqueAccessToken(t, rec)
				return rec.ID
			},
		},
	}
	for _, cfg := range configs {
		for _, format := range formats {
			t.Run(cfg.name+"/"+format.name, func(t *testing.T) {
				t.Parallel()

				f := newUserInfoFixtureWithOptions(t, cfg.opts...)
				f.putUser(t, fixtureClientID, map[string]any{"email": "collision@example.com"})

				resp := f.doRequest(t, f.newGet(t, format.token(t, f)))
				defer resp.Body.Close()
				if resp.StatusCode != http.StatusUnauthorized {
					t.Fatalf("status=%d want 401", resp.StatusCode)
				}
				if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, `error="invalid_token"`) {
					t.Errorf("WWW-Authenticate=%q must declare invalid_token", got)
				}
				assertNoClaimLeak(t, resp)
			})
		}
	}
}
