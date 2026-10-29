package revokeendpoint_test

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// TestHandler_RefreshToken_ExchangeChainLeavesSubjectClientGrant pins that
// revoking a token-exchange refresh token retires that chain and its own
// opaque access tokens, and nothing the subject client holds in the grant
// the chain joined.
func TestHandler_RefreshToken_ExchangeChainLeavesSubjectClientGrant(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	exchanger, secret := f.confidentialClient(t, "client-exchanger")
	const grantID = "grant-of-subject-client"

	seedRT := func(id, clientID, chainID string, origin store.RefreshTokenOrigin) {
		f.saveRefreshToken(t, &store.RefreshToken{
			ID:        id,
			ClientID:  clientID,
			Subject:   "user-1",
			GrantID:   grantID,
			ChainID:   chainID,
			Origin:    origin,
			Scope:     []string{"openid"},
			ExpiresAt: f.clock.now.Add(24 * time.Hour),
			CreatedAt: f.clock.now,
		})
	}
	seedAT := func(id, clientID, chainID string) {
		f.saveOpaqueAccessToken(t, &store.OpaqueAccessToken{
			ID:        id,
			ClientID:  clientID,
			Subject:   "user-1",
			GrantID:   grantID,
			ChainID:   chainID,
			Scope:     []string{"openid"},
			IssuedAt:  f.clock.now,
			ExpiresAt: f.clock.now.Add(time.Hour),
		})
	}
	seedRT("rt-exchanged", exchanger.ID, "chain-exchanged", store.RefreshOriginCustomGrant)
	seedRT("rt-subject-client", "client-subject", "chain-subject", store.RefreshOriginAuthCode)
	seedAT("at-exchanged", exchanger.ID, "chain-exchanged")
	seedAT("at-subject-client", "client-subject", "chain-subject")

	form := url.Values{"token": {"rt-exchanged"}, "token_type_hint": {"refresh_token"}}
	resp := f.post(t, form, exchanger.ID, secret)
	defer resp.Body.Close()
	assertEmptySuccess(t, resp)

	assertConsumedOrGone(t, f, "rt-exchanged")
	ctx := context.Background()
	if rt, err := f.prov.Store.RefreshTokens().Find(ctx, "rt-subject-client"); err != nil || rt == nil || rt.ConsumedAt != nil {
		t.Errorf("subject client's refresh token retired by the exchanger's revoke: rec=%+v err=%v", rt, err)
	}
	if at, err := f.prov.Store.OpaqueAccessTokens().Find(ctx, "at-subject-client"); err != nil || at == nil || at.Revoked {
		t.Errorf("subject client's access token revoked by the exchanger's revoke: rec=%+v err=%v", at, err)
	}
	if at, err := f.prov.Store.OpaqueAccessTokens().Find(ctx, "at-exchanged"); err == nil && at != nil && !at.Revoked {
		t.Errorf("exchanged chain's own access token still live after revoke")
	}
}
