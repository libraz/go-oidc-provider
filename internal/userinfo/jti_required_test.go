package userinfo_test

import (
	"net/http"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
)

// TestUserInfo_JTILessTokenRejectedUnderJTIRegistry pins the revocation
// floor at the /userinfo surface: with the registry strategy configured,
// a JWT access token carrying no "jti" is refused outright rather than
// verified and then waved through.
//
// Without the check the token reaches the revocation probe, which looks
// the token up by jti alone, finds no row for the empty key, and reports
// "not revoked" — so a token that revocation can never reach reads as
// permanently live. The bearer is answered with the user's claims.
func TestUserInfo_JTILessTokenRejectedUnderJTIRegistry(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixtureWithOptions(t,
		op.WithAccessTokenRevocationStrategy(op.AccessTokenRevocationStrategy(store.RevocationStrategyJTIRegistry)),
	)
	f.putUser(t, "user-1", map[string]any{"email": "user@example.test"})

	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) { c.JTI = "" })
	resp := f.doRequest(t, f.newGet(t, token))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; a token with no jti cannot be revoked through the registry, "+
			"so accepting it makes revocation unreachable for its whole lifetime", resp.StatusCode)
	}
}

// TestUserInfo_JTIBearingTokenStillAcceptedUnderJTIRegistry is the
// control: the requirement must reject only the unrevocable shape, not
// every token. Both mint sites always emit a jti, so this is the case
// production actually produces.
func TestUserInfo_JTIBearingTokenStillAcceptedUnderJTIRegistry(t *testing.T) {
	t.Parallel()

	f := newUserInfoFixtureWithOptions(t,
		op.WithAccessTokenRevocationStrategy(op.AccessTokenRevocationStrategy(store.RevocationStrategyJTIRegistry)),
	)
	f.putUser(t, "user-1", map[string]any{"email": "user@example.test"})

	token := f.signAccessToken(t, nil)
	resp := f.doRequest(t, f.newGet(t, token))
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a normally-minted token", resp.StatusCode)
	}
}
