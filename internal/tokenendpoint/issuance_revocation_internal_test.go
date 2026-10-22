package tokenendpoint

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// grantRevocationsOnly hides every optional capability of the wrapped
// substore, the way a bring-your-own store that predates them looks.
type grantRevocationsOnly struct{ store.GrantRevocationStore }

// An access-token-only tombstone leaves issuance open only where the store
// can tell it apart; anywhere else issuance is refused as before.
func TestGrantClosedToIssuance_FallsBackToEveryTombstone(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	revs := inmem.New().GrantRevocations()
	if err := revs.RevokeGrant(ctx, store.GrantTombstone{
		GrantID: "grant-1", RevokedAt: now, ExpiresAt: now.Add(time.Hour), AccessTokensOnly: true,
	}); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	issuedAt := now.Add(-time.Minute)

	if closed, err := grantClosedToIssuance(ctx, revs, "grant-1", issuedAt); err != nil || closed {
		t.Errorf("checker-capable store: closed=%v err=%v, want open", closed, err)
	}
	if closed, err := grantClosedToIssuance(ctx, grantRevocationsOnly{revs}, "grant-1", issuedAt); err != nil || !closed {
		t.Errorf("store without the checker: closed=%v err=%v, want closed", closed, err)
	}
}
