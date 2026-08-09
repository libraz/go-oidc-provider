//go:build testcontainers

package oidcdynamo_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
)

// transactionItemLimit mirrors the TransactWriteItems action ceiling the
// adapter is bounded by. It is duplicated here rather than exported:
// the limit belongs to the service, and a test that hard-codes it fails
// if the adapter ever silently adopts a different one.
const transactionItemLimit = 100

// TestTx_CascadeRollbackLeavesEveryTokenLive pins the property every
// revocation cascade driven from a [store.Tx] depends on: nothing it
// retires reaches the table before Commit.
//
// The cascades are the three the OP runs together — the refresh chain,
// the JWT registry, and the opaque tokens — because they are retired by
// per-record writes rather than by a single row, which is the shape that
// invites a write-through. A cascade that wrote through would log the
// user out of a grant on the strength of a request that then failed, and
// no amount of rolling back would bring the tokens back.
func TestTx_CascadeRollbackLeavesEveryTokenLive(t *testing.T) {
	t.Parallel()

	s := newIsolatedStore(t, "txcascade_")
	ctx := t.Context()
	const grantID = "grant-cascade"

	root := newRotationToken("rt-cascade-root", nil)
	root.GrantID = grantID
	child := newRotationToken("rt-cascade-child", &root.ID)
	child.GrantID = grantID
	for _, rt := range []*store.RefreshToken{root, child} {
		if err := s.RefreshTokens().Save(ctx, rt); err != nil {
			t.Fatalf("Save %s: %v", rt.ID, err)
		}
	}
	jtis := []string{"jti-cascade-a", "jti-cascade-b"}
	for _, jti := range jtis {
		if err := s.AccessTokens().Register(ctx, newRegisteredAccessToken(jti, grantID)); err != nil {
			t.Fatalf("Register %s: %v", jti, err)
		}
	}
	opaques := []string{"oat-cascade-a", "oat-cascade-b"}
	for _, id := range opaques {
		if err := s.OpaqueAccessTokens().Save(ctx, newOpaqueToken(id, grantID)); err != nil {
			t.Fatalf("Save opaque %s: %v", id, err)
		}
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := tx.RefreshTokens().RevokeByGrant(ctx, grantID); err != nil {
		t.Fatalf("tx RefreshTokens().RevokeByGrant: %v", err)
	}
	registered, err := tx.AccessTokens().RevokeByGrant(ctx, grantID)
	if err != nil {
		t.Fatalf("tx AccessTokens().RevokeByGrant: %v", err)
	}
	if registered != len(jtis) {
		t.Errorf("tx AccessTokens().RevokeByGrant count = %d, want %d", registered, len(jtis))
	}
	opaque, err := tx.OpaqueAccessTokens().RevokeByGrant(ctx, grantID)
	if err != nil {
		t.Fatalf("tx OpaqueAccessTokens().RevokeByGrant: %v", err)
	}
	if opaque != len(opaques) {
		t.Errorf("tx OpaqueAccessTokens().RevokeByGrant count = %d, want %d", opaque, len(opaques))
	}

	// The transaction reads its own cascade: a handler that re-reads a
	// record it has just retired must not see it as live.
	for _, id := range []string{root.ID, child.ID} {
		got, err := tx.RefreshTokens().Find(ctx, id)
		if err != nil {
			t.Fatalf("tx Find %s: %v", id, err)
		}
		if !got.Revoked || got.ConsumedAt == nil {
			t.Errorf("refresh token %s reads as live inside the revoking tx: %+v", id, got)
		}
	}
	for _, jti := range jtis {
		got, err := tx.AccessTokens().Find(ctx, jti)
		if err != nil {
			t.Fatalf("tx AccessTokens().Find %s: %v", jti, err)
		}
		if got == nil || !got.Revoked {
			t.Errorf("access token %s reads as live inside the revoking tx: %+v", jti, got)
		}
	}
	for _, id := range opaques {
		got, err := tx.OpaqueAccessTokens().Find(ctx, id)
		if err != nil {
			t.Fatalf("tx OpaqueAccessTokens().Find %s: %v", id, err)
		}
		if !got.Revoked {
			t.Errorf("opaque access token %s reads as live inside the revoking tx: %+v", id, got)
		}
	}

	if err := tx.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	for _, id := range []string{root.ID, child.ID} {
		got, err := s.RefreshTokens().Find(ctx, id)
		if err != nil {
			t.Fatalf("Find %s after Rollback: %v", id, err)
		}
		if got.Revoked || got.ConsumedAt != nil {
			t.Errorf("refresh token %s was retired by a rolled-back tx: %+v", id, got)
		}
	}
	for _, jti := range jtis {
		got, err := s.AccessTokens().Find(ctx, jti)
		if err != nil {
			t.Fatalf("AccessTokens().Find %s after Rollback: %v", jti, err)
		}
		if got == nil || got.Revoked {
			t.Errorf("access token %s was retired by a rolled-back tx: %+v", jti, got)
		}
	}
	for _, id := range opaques {
		got, err := s.OpaqueAccessTokens().Find(ctx, id)
		if err != nil {
			t.Fatalf("OpaqueAccessTokens().Find %s after Rollback: %v", id, err)
		}
		if got.Revoked {
			t.Errorf("opaque access token %s was retired by a rolled-back tx: %+v", id, got)
		}
	}
}

// TestTx_RevokeChainTransactionCeiling pins what a chain cascade costs a
// transaction. Buffering the walk makes it atomic, and the price is that
// it is bounded: one action per node against a ceiling the service sets.
//
// Both directions matter. A chain that fits has to commit — the ceiling
// is inclusive, and an off-by-one here would reject cascades that are
// perfectly legal. A chain that does not fit has to fail as
// [oidcdynamo.ErrTransactionTooLarge], not as an opaque service
// validation error the caller cannot distinguish from a backend fault,
// and it must not have retired part of the chain on the way there.
func TestTx_RevokeChainTransactionCeiling(t *testing.T) {
	t.Parallel()

	s := newIsolatedStore(t, "txceiling_")

	t.Run("ChainAtTheLimitCommits", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		chain := seedRefreshChain(t, s, ctx, "atlimit", transactionItemLimit)

		tx, err := s.BeginTx(ctx)
		if err != nil {
			t.Fatalf("BeginTx: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		if err := tx.RefreshTokens().RevokeChain(ctx, chain[0]); err != nil {
			t.Fatalf("tx RevokeChain over %d nodes: %v", len(chain), err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("Commit: %v", err)
		}
		for _, id := range chain {
			got, err := s.RefreshTokens().Find(ctx, id)
			if err != nil {
				t.Fatalf("Find %s after Commit: %v", id, err)
			}
			if !got.Revoked || got.ConsumedAt == nil {
				t.Fatalf("token %s survived the committed cascade: %+v", id, got)
			}
		}
	})

	t.Run("ChainBeyondTheLimitIsRejected", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		chain := seedRefreshChain(t, s, ctx, "overlimit", transactionItemLimit+1)

		tx, err := s.BeginTx(ctx)
		if err != nil {
			t.Fatalf("BeginTx: %v", err)
		}
		defer func() { _ = tx.Rollback() }()
		err = tx.RefreshTokens().RevokeChain(ctx, chain[0])
		if !errors.Is(err, oidcdynamo.ErrTransactionTooLarge) {
			t.Fatalf("tx RevokeChain over %d nodes = %v, want ErrTransactionTooLarge", len(chain), err)
		}
		if err := tx.Rollback(); err != nil {
			t.Fatalf("Rollback: %v", err)
		}
		// The walk gave up before staging the node that would not fit, and
		// staging is all it ever did: the chain is untouched.
		for _, id := range chain {
			got, err := s.RefreshTokens().Find(ctx, id)
			if err != nil {
				t.Fatalf("Find %s after the rejected cascade: %v", id, err)
			}
			if got.Revoked || got.ConsumedAt != nil {
				t.Fatalf("token %s was retired by a cascade that never committed: %+v", id, got)
			}
		}
	})
}

// seedRefreshChain stores a linear rotation chain of n tokens through
// the non-transactional path and returns their ids, root first.
func seedRefreshChain(
	t *testing.T,
	s *oidcdynamo.Store,
	ctx context.Context,
	label string,
	n int,
) []string {
	t.Helper()
	ids := make([]string, 0, n)
	var parent *string
	for i := range n {
		id := fmt.Sprintf("rt-%s-%03d", label, i)
		tok := newRotationToken(id, parent)
		tok.GrantID = "grant-" + label
		if err := s.RefreshTokens().Save(ctx, tok); err != nil {
			t.Fatalf("Save %s: %v", id, err)
		}
		ids = append(ids, id)
		previous := id
		parent = &previous
	}
	return ids
}

func newRegisteredAccessToken(jti, grantID string) store.AccessTokenRecord {
	return store.AccessTokenRecord{
		JTI:       jti,
		GrantID:   grantID,
		Subject:   "sub-cascade",
		ClientID:  "client-cascade",
		Scopes:    []string{"openid"},
		IssuedAt:  contract.Reference,
		ExpiresAt: contract.Reference.Add(time.Hour),
	}
}

func newOpaqueToken(id, grantID string) *store.OpaqueAccessToken {
	return &store.OpaqueAccessToken{
		ID:        id,
		GrantID:   grantID,
		Subject:   "sub-cascade",
		ClientID:  "client-cascade",
		Scope:     []string{"openid"},
		IssuedAt:  contract.Reference,
		ExpiresAt: contract.Reference.Add(time.Hour),
	}
}
