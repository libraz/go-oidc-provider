package userinfo_test

import (
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// The grant a token descends from is shared by every authorization of the
// (subject, client_id) pair, so its claims request is whichever
// authorization ran last. A token carries the request it was issued under;
// these tests present tokens whose own request differs from the grant's.

func userInfoClaimsRequestFor(name string) map[string]any {
	return authorize.EncodeClaimsToGrant(&authorize.ClaimsRequest{
		UserInfo: map[string]authorize.ClaimSpec{name: {}},
	})
}

// assertReleased checks the response releases want and nothing named
// withheld; neither is scope-derived, the token being "openid" only.
func assertReleased(tb testing.TB, resp *http.Response, want, wantVal, withheld string) {
	tb.Helper()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		tb.Fatalf("status=%d body=%s", resp.StatusCode, dump)
	}
	body := decodeBody(tb, resp)
	if want != "" && body[want] != wantVal {
		tb.Errorf("%s=%v want %q from the token's own claims request", want, body[want], wantVal)
	}
	if got, ok := body[withheld]; ok {
		tb.Errorf("%s=%v released from the grant's claims request", withheld, got)
	}
}

// TestHandler_JWTAccessToken_ClaimsRequestComesFromTheToken presents a JWT
// whose userinfo_claims asks for phone_number while its grant asks for
// email.
func TestHandler_JWTAccessToken_ClaimsRequestComesFromTheToken(t *testing.T) {
	t.Parallel()

	f := seedGrantIsolationFixture(t)
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Subject = grantIsolationSubject
		c.GrantID = grantIsolationOlderID
		c.Scope = []string{"openid"}
		c.UserInfoClaims = userInfoClaimsRequestFor(grantIsolationNewerCl)
	})

	resp := f.doRequest(t, f.newGet(t, token))
	defer resp.Body.Close()
	assertReleased(t, resp, grantIsolationNewerCl, grantIsolationNewerVal, grantIsolationOlderCl)
}

// TestHandler_JWTAccessToken_EmptyClaimsRequestIsNotFilledFromTheGrant
// presents a JWT minted under an authorization that requested no userinfo
// claims.
func TestHandler_JWTAccessToken_EmptyClaimsRequestIsNotFilledFromTheGrant(t *testing.T) {
	t.Parallel()

	f := seedGrantIsolationFixture(t)
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Subject = grantIsolationSubject
		c.GrantID = grantIsolationOlderID
		c.Scope = []string{"openid"}
		c.UserInfoClaims = map[string]any{}
	})

	resp := f.doRequest(t, f.newGet(t, token))
	defer resp.Body.Close()
	assertReleased(t, resp, "", "", grantIsolationOlderCl)
}

// TestHandler_OpaqueAccessToken_ClaimsRequestComesFromTheToken is the
// opaque-format counterpart, with the request on the token's record.
func TestHandler_OpaqueAccessToken_ClaimsRequestComesFromTheToken(t *testing.T) {
	t.Parallel()

	f := seedGrantIsolationFixture(t)
	rec := &store.OpaqueAccessToken{
		ID:                    "opaque-own-claims-request",
		GrantID:               grantIsolationOlderID,
		ClientID:              fixtureClientID,
		Subject:               grantIsolationSubject,
		Scope:                 []string{"openid"},
		Claims:                userInfoClaimsRequestFor(grantIsolationNewerCl),
		AuthorizationRecorded: true,
		IssuedAt:              f.clock.now,
		ExpiresAt:             f.clock.now.Add(time.Hour),
	}
	f.saveOpaqueAccessToken(t, rec)

	resp := f.doRequest(t, f.newGet(t, rec.ID))
	defer resp.Body.Close()
	assertReleased(t, resp, grantIsolationNewerCl, grantIsolationNewerVal, grantIsolationOlderCl)
}
