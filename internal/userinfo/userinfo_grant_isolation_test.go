package userinfo_test

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Two grants held by the same (subject, client_id) pair, each carrying a
// different OIDC Core 1.0 §5.5 "claims" payload. Grant Management's
// "create" action mints a fresh grant on every authorization, so a client
// that has authorized twice legitimately holds both at once; the newer one
// is what a (subject, client_id) search resolves to, which is why the
// older one is the interesting lineage to present a token from.
const (
	grantIsolationSubject  = "user-grant-isolation"
	grantIsolationOlderID  = "grant-isolation-older"
	grantIsolationNewerID  = "grant-isolation-newer"
	grantIsolationOlderCl  = "email"
	grantIsolationNewerCl  = "phone_number"
	grantIsolationOlderVal = "authorized@example.com"
	grantIsolationNewerVal = "+1-555-0199"
)

// seedGrantIsolationFixture registers the user and the two competing
// grants, and returns the fixture. The user record holds the claim data
// for both grants so that whichever §5.5 payload the handler projects,
// the value is available — an absent source value would make the
// assertion pass for the wrong reason.
func seedGrantIsolationFixture(tb testing.TB) *userInfoFixture {
	tb.Helper()
	f := newUserInfoFixture(tb)
	f.putUser(tb, grantIsolationSubject, map[string]any{
		grantIsolationOlderCl: grantIsolationOlderVal,
		grantIsolationNewerCl: grantIsolationNewerVal,
	})
	saveGrantWithUserInfoClaim(tb, f, grantIsolationOlderID, grantIsolationOlderCl, f.clock.now)
	saveGrantWithUserInfoClaim(tb, f, grantIsolationNewerID, grantIsolationNewerCl, f.clock.now.Add(time.Minute))
	return f
}

// saveGrantWithUserInfoClaim persists a grant whose §5.5 payload requests
// exactly one claim at the userinfo location. The payload is built through
// [authorize.EncodeClaimsToGrant] so the test depends on the encoder
// contract rather than on the storage key it happens to use.
func saveGrantWithUserInfoClaim(tb testing.TB, f *userInfoFixture, grantID, claimName string, updatedAt time.Time) {
	tb.Helper()
	encoded := authorize.EncodeClaimsToGrant(&authorize.ClaimsRequest{
		UserInfo: map[string]authorize.ClaimSpec{claimName: {}},
	})
	if err := f.prov.Store.Grants().Save(context.Background(), &store.Grant{
		ID:        grantID,
		Subject:   grantIsolationSubject,
		ClientID:  fixtureClientID,
		Scope:     []string{"openid"},
		Claims:    encoded,
		CreatedAt: f.clock.now,
		UpdatedAt: updatedAt,
	}); err != nil {
		tb.Fatalf("Grants.Save(%s): %v", grantID, err)
	}
}

// assertGrantIsolatedClaims checks that the response projects the §5.5
// payload of the grant the presented token descends from and nothing
// from its sibling. The token is granted "openid" only, so neither claim
// is scope-derived and the §5.5 payload is the sole release path.
func assertGrantIsolatedClaims(tb testing.TB, resp *http.Response) {
	tb.Helper()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		tb.Fatalf("status=%d body=%s", resp.StatusCode, dump)
	}
	body := decodeBody(tb, resp)
	if got := body[grantIsolationOlderCl]; got != grantIsolationOlderVal {
		tb.Errorf("%s=%v want %q from the token's own grant", grantIsolationOlderCl, got, grantIsolationOlderVal)
	}
	if got, ok := body[grantIsolationNewerCl]; ok {
		tb.Errorf("%s=%v released from a sibling grant the token does not descend from",
			grantIsolationNewerCl, got)
	}
}

// TestHandler_JWTAccessToken_ClaimsComeFromItsOwnGrant presents a JWT
// access token whose "gid" names the older of two grants and requires the
// response to carry only that grant's §5.5 claims. Resolving the payload
// by (subject, client_id) instead would answer with the newer grant and
// release a claim outside the presented token's authorization.
func TestHandler_JWTAccessToken_ClaimsComeFromItsOwnGrant(t *testing.T) {
	t.Parallel()

	f := seedGrantIsolationFixture(t)
	token := f.signAccessToken(t, func(c *tokens.AccessTokenClaims) {
		c.Subject = grantIsolationSubject
		c.GrantID = grantIsolationOlderID
		c.Scope = []string{"openid"}
	})

	resp := f.doRequest(t, f.newGet(t, token))
	defer resp.Body.Close()
	assertGrantIsolatedClaims(t, resp)
}

// TestHandler_OpaqueAccessToken_ClaimsComeFromItsOwnGrant is the
// opaque-format counterpart: the lineage lives in the record's GrantID
// column rather than in a JWT claim, and the same isolation must hold.
func TestHandler_OpaqueAccessToken_ClaimsComeFromItsOwnGrant(t *testing.T) {
	t.Parallel()

	f := seedGrantIsolationFixture(t)
	rec := &store.OpaqueAccessToken{
		ID:        "opaque-grant-isolation",
		GrantID:   grantIsolationOlderID,
		ClientID:  fixtureClientID,
		Subject:   grantIsolationSubject,
		Scope:     []string{"openid"},
		IssuedAt:  f.clock.now,
		ExpiresAt: f.clock.now.Add(time.Hour),
	}
	f.saveOpaqueAccessToken(t, rec)

	resp := f.doRequest(t, f.newGet(t, rec.ID))
	defer resp.Body.Close()
	assertGrantIsolatedClaims(t, resp)
}
