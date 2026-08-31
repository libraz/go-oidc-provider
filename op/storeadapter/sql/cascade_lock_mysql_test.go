//go:build testcontainers

package oidcsql_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// The deleted client holds a minority of the table's tokens, which is
// the shape a real deployment has and the shape the difference is
// visible in: a client whose rows are nearly the whole table is one the
// optimiser would scan for on purpose, so seeding only the victim would
// test the optimiser's arithmetic rather than the schema.
const (
	cascadeTokensPerClient = 100
	cascadeBystanderClient = 10
)

// bystanderClient sorts before the deleted client so the bystander's row
// is not adjacent to the locked index range by accident. What the test
// asserts is that the range is bounded at all.
const (
	bystanderClient = "aaa-bystander"
	deletedClient   = "zzz-deleted"
)

// TestMySQL_ClientCascadeLeavesOtherClientsUsable is the acceptance the
// query plan cannot give. Deleting a dynamically registered client
// revokes its outstanding tokens with an UPDATE filtered on client_id,
// and under InnoDB's repeatable read the statement locks every row it
// examines rather than every row it changes. Filtered on an unindexed
// column that is the whole table, so every concurrent refresh and
// introspection queues behind a single client deletion.
//
// The cascade is held open in a transaction here so its locks are still
// in place when another client's token is redeemed. The redemption has a
// deadline: blocking is the failure, and without a deadline it would
// show up as the test hanging rather than as a result.
func TestMySQL_ClientCascadeLeavesOtherClientsUsable(t *testing.T) {
	t.Parallel()

	b := newMySQLFactory(t)(t)
	s, ok := b.Store.(*oidcsql.Store)
	if !ok {
		t.Fatalf("factory produced %T, want *oidcsql.Store", b.Store)
	}
	ctx := context.Background()
	now := b.Now()

	cascadeToken := func(client, id string) *store.RefreshToken {
		return &store.RefreshToken{
			ID:        id,
			ClientID:  client,
			Subject:   "cascade-subject",
			GrantID:   "cascade-grant",
			Scope:     []string{"openid", "offline_access"},
			ExpiresAt: now.Add(24 * time.Hour),
			CreatedAt: now,
		}
	}
	for i := range cascadeTokensPerClient {
		if err := s.RefreshTokens().Save(ctx, cascadeToken(deletedClient, fmt.Sprintf("cascade-%d", i))); err != nil {
			t.Fatalf("seed token %d: %v", i, err)
		}
	}
	for c := range cascadeBystanderClient {
		for i := range cascadeTokensPerClient {
			id := fmt.Sprintf("other-%d-%d", c, i)
			if err := s.RefreshTokens().Save(ctx, cascadeToken(fmt.Sprintf("other-client-%d", c), id)); err != nil {
				t.Fatalf("seed %s: %v", id, err)
			}
		}
	}
	const bystanderToken = "bystander-token"
	if err := s.RefreshTokens().Save(ctx, cascadeToken(bystanderClient, bystanderToken)); err != nil {
		t.Fatalf("seed the bystander token: %v", err)
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	cascade, ok := tx.RefreshTokens().(store.RevokeByClient)
	if !ok {
		t.Fatal("the tx-bound RefreshTokenStore does not implement RevokeByClient")
	}
	if err := cascade.RevokeByClient(ctx, deletedClient); err != nil {
		t.Fatalf("RevokeByClient: %v", err)
	}

	redeem, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := s.RefreshTokens().Consume(redeem, bystanderToken); err != nil {
		t.Fatalf("redeeming another client's refresh token while the cascade holds its locks: %v\n"+
			"the cascade is locking rows it does not revoke, so a client deletion stalls every concurrent refresh", err)
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit the cascade: %v", err)
	}
	revoked, err := s.RefreshTokens().Find(ctx, "cascade-0")
	if err != nil {
		t.Fatalf("Find a revoked token: %v", err)
	}
	if !revoked.Revoked {
		t.Error("the cascade committed without revoking the deleted client's tokens")
	}
}
