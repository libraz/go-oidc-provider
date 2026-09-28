package userinfo_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// TestHandler_DeletedClientTokensRejected pins that removing a client
// through the registry alone, with no revocation cascade, stops its
// access tokens at /userinfo in both formats.
func TestHandler_DeletedClientTokensRejected(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		token func(t *testing.T, f *userInfoFixture) string
	}{
		{
			name: "jwt access token",
			token: func(t *testing.T, f *userInfoFixture) string {
				t.Helper()
				return f.signAccessToken(t, func(c *tokens.AccessTokenClaims) { c.Subject = "user-orphaned" })
			},
		},
		{
			name: "opaque access token",
			token: func(t *testing.T, f *userInfoFixture) string {
				t.Helper()
				rec := &store.OpaqueAccessToken{
					ID:        "opaque-userinfo-orphaned",
					GrantID:   "grant-orphaned",
					ClientID:  fixtureClientID,
					Subject:   "user-orphaned",
					Scope:     []string{"openid", "email"},
					IssuedAt:  f.clock.now,
					ExpiresAt: f.clock.now.Add(time.Hour),
				}
				f.saveOpaqueAccessToken(t, rec)
				return rec.ID
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			f := newUserInfoFixture(t)
			f.putUser(t, "user-orphaned", map[string]any{"email": "orphan@example.com"})
			token := tc.token(t, f)

			before := f.doRequest(t, f.newGet(t, token))
			before.Body.Close()
			if before.StatusCode != http.StatusOK {
				t.Fatalf("precondition: status=%d before the client was deleted", before.StatusCode)
			}
			if err := f.prov.Store.DeleteClient(context.Background(), fixtureClientID); err != nil {
				t.Fatalf("DeleteClient: %v", err)
			}

			resp := f.doRequest(t, f.newGet(t, token))
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status=%d want 401 after the client was deleted", resp.StatusCode)
			}
			if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, `error="invalid_token"`) {
				t.Errorf("WWW-Authenticate=%q must declare invalid_token", got)
			}
			assertNoClaimLeak(t, resp)
		})
	}
}
