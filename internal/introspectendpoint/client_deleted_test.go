package introspectendpoint_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// TestHandler_DeletedClientTokensInactive pins that removing a client
// through the registry alone, with no revocation cascade, retires its
// access tokens at /introspect in both formats. A resource server that
// is itself still registered does the asking, since the deleted client
// can no longer authenticate.
func TestHandler_DeletedClientTokensInactive(t *testing.T) {
	t.Parallel()

	t.Run("jwt access token", func(t *testing.T) {
		t.Parallel()

		f := newDelegationFixture(t)
		token := f.jwtFor(t, delegatedResource)
		if !f.introspectAs(t, gatewayClientID, token) {
			t.Fatal("precondition: token inactive before the client was deleted")
		}
		if err := f.prov.Store.DeleteClient(context.Background(), tokenClientID); err != nil {
			t.Fatalf("DeleteClient: %v", err)
		}
		if f.introspectAs(t, gatewayClientID, token) {
			t.Error("JWT access token of a deleted client introspected active")
		}
	})

	t.Run("opaque access token", func(t *testing.T) {
		t.Parallel()

		f := newDelegationFixture(t)
		rec := &store.OpaqueAccessToken{
			ID:        "opaque-orphaned-1",
			ClientID:  tokenClientID,
			Subject:   "user-orphaned",
			Scope:     []string{"openid"},
			Audience:  delegatedResource,
			IssuedAt:  f.clock.now,
			ExpiresAt: f.clock.now.Add(time.Hour),
		}
		f.saveOpaqueAccessToken(t, rec)
		if !f.introspectAs(t, gatewayClientID, rec.ID) {
			t.Fatal("precondition: token inactive before the client was deleted")
		}
		if err := f.prov.Store.DeleteClient(context.Background(), tokenClientID); err != nil {
			t.Fatalf("DeleteClient: %v", err)
		}
		if f.introspectAs(t, gatewayClientID, rec.ID) {
			t.Error("opaque access token of a deleted client introspected active")
		}
	})
}
