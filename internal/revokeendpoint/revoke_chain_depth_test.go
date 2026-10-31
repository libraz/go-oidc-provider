package revokeendpoint_test

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// chainDepthBeyondWalkLimit is a rotation depth deeper than the parent-walk
// limit internal/revocation applies. The limit is unexported, so the
// fixture names a depth known to exceed it.
const chainDepthBeyondWalkLimit = 1100

// TestHandler_RefreshToken_ChainDeeperThanWalkLimitIsRevoked pins that chain
// depth never decides whether /revoke retires a refresh token: a client that
// has kept refreshing past the walk limit still gets the presented token, its
// successors and the grant's access tokens revoked.
func TestHandler_RefreshToken_ChainDeeperThanWalkLimitIsRevoked(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClient(t, "client-rt-deep")
	const grantID = "grant-rt-deep"

	ids := make([]string, 0, chainDepthBeyondWalkLimit+2)
	for i := range chainDepthBeyondWalkLimit + 2 {
		id := fmt.Sprintf("rt-deep-%04d", i)
		rec := &store.RefreshToken{
			ID:        id,
			ClientID:  client.ID,
			Subject:   "user-deep",
			GrantID:   grantID,
			Scope:     []string{"openid"},
			ExpiresAt: f.clock.now.Add(24 * time.Hour),
			CreatedAt: f.clock.now,
		}
		if n := len(ids); n > 0 {
			parent := ids[n-1]
			rec.ParentID = &parent
		}
		f.saveRefreshToken(t, rec)
		ids = append(ids, id)
	}
	f.saveOpaqueAccessToken(t, &store.OpaqueAccessToken{
		ID:        "at-deep-1",
		ClientID:  client.ID,
		Subject:   "user-deep",
		GrantID:   grantID,
		Scope:     []string{"openid"},
		IssuedAt:  f.clock.now,
		ExpiresAt: f.clock.now.Add(time.Hour),
	})

	presented := ids[len(ids)-2]
	form := url.Values{"token": {presented}, "token_type_hint": {"refresh_token"}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	assertEmptySuccess(t, resp)

	assertConsumedOrGone(t, f, presented)
	assertConsumedOrGone(t, f, ids[len(ids)-1])

	got, err := f.prov.Store.OpaqueAccessTokens().Find(context.Background(), "at-deep-1")
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find access token after refresh revoke: %v", err)
	}
	if err == nil && (got == nil || !got.Revoked) {
		t.Errorf("access token under grant still live after deep-chain revoke; got=%+v", got)
	}
}
