//go:build testcontainers

package oidcdynamo_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
)

// newRotationToken builds a refresh token the rotation tests can save
// under either end of a chain.
func newRotationToken(id string, parent *string) *store.RefreshToken {
	return &store.RefreshToken{
		ID:        id,
		ClientID:  "client-rotation",
		GrantID:   "grant-rotation",
		Subject:   "sub-rotation",
		ParentID:  parent,
		Scope:     []string{"openid"},
		ExpiresAt: contract.Reference.Add(time.Hour),
		CreatedAt: contract.Reference,
	}
}

// requireRetryStore reaches the RFC 9700 grace-window extension on a
// refresh substore.
func requireRetryStore(t *testing.T, refreshes store.RefreshTokenStore) store.RefreshRetryResponseStore {
	t.Helper()
	retry, ok := refreshes.(store.RefreshRetryResponseStore)
	if !ok {
		t.Fatalf("%T does not implement store.RefreshRetryResponseStore", refreshes)
	}
	return retry
}

// TestRefreshRotation_RejectedRetryCacheLeavesNoSuccessor pins the
// all-or-nothing property of SaveRotationWithRetry against a cache write
// the predecessor's own state turns away, and the parity with Save for
// the one case that is not a rejection at all.
//
// A successor that outlived a failed cache write would be the worst of
// both worlds: the client sees only the error, retries with the
// predecessor it still holds, finds no cached response, and the
// presentation is taken for a replay — revoking a chain it legitimately
// owns. The contract harness pins the successful rotation; this pins
// what the table looks like after an unsuccessful one.
func TestRefreshRotation_RejectedRetryCacheLeavesNoSuccessor(t *testing.T) {
	t.Parallel()

	s := newIsolatedStore(t, "rotretry_")
	refreshes := s.RefreshTokens()
	retry := requireRetryStore(t, refreshes)

	// A predecessor that is simply gone is not a rejection: an absent
	// parent proves the chain was never revoked, which is exactly what
	// Save concludes from the same input. The rotation is kept and only
	// the cache — the optional half — is dropped, since there is no row
	// left to attach it to and LoadRetryResponse already answers
	// ErrNotFound for a predecessor that has none.
	t.Run("PredecessorGoneKeepsTheRotation", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		parentID := "rt-gone-predecessor"
		successor := newRotationToken("rt-gone-successor", &parentID)

		if err := retry.SaveRotationWithRetry(ctx, successor, []byte("sealed")); err != nil {
			t.Fatalf("SaveRotationWithRetry without a predecessor = %v, want the success Save reports", err)
		}
		if _, err := refreshes.Find(ctx, successor.ID); err != nil {
			t.Fatalf("the rotation was rolled back because its cache had no predecessor row: Find = %v", err)
		}
		if _, err := retry.LoadRetryResponse(ctx, parentID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("LoadRetryResponse for a predecessor that never existed = %v, want ErrNotFound", err)
		}
	})

	t.Run("PredecessorChainRevoked", func(t *testing.T) {
		t.Parallel()
		ctx := t.Context()
		predecessor := newRotationToken("rt-revoked-predecessor", nil)
		if err := refreshes.Save(ctx, predecessor); err != nil {
			t.Fatalf("Save predecessor: %v", err)
		}
		if err := refreshes.RevokeChain(ctx, predecessor.ID); err != nil {
			t.Fatalf("RevokeChain: %v", err)
		}

		successor := newRotationToken("rt-revoked-successor", &predecessor.ID)
		err := retry.SaveRotationWithRetry(ctx, successor, []byte("sealed"))
		if !errors.Is(err, store.ErrAlreadyConsumed) {
			t.Fatalf("SaveRotationWithRetry onto a revoked chain = %v, want ErrAlreadyConsumed", err)
		}
		if _, err := refreshes.Find(ctx, successor.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("successor survived the rejected rotation: Find = %v, want ErrNotFound", err)
		}
		if _, err := retry.LoadRetryResponse(ctx, predecessor.ID); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("retry response was cached despite the rejected rotation: %v", err)
		}
	})
}

// TestRefreshRotation_RetryResponseLapsesWithPredecessor pins the
// retention bound on the sealed grace-window response: it may be kept
// no longer than the predecessor's own refresh-token lifetime.
//
// The contract harness pins the same rule, but reaches the live-to-
// expired transition only for backends that hand it a movable clock;
// the shared DynamoDB factory pins one instant per suite, so the
// transition is covered here. It is the half that matters most: a cache
// which simply outlives its predecessor still answers every other retry
// case correctly while re-delivering a token set for a credential the
// endpoint has already stopped accepting.
//
// The successor deliberately outlives the predecessor, so the assertion
// distinguishes the predecessor's own lifetime from the chain's.
func TestRefreshRotation_RetryResponseLapsesWithPredecessor(t *testing.T) {
	t.Parallel()

	s, clock := newMovingClockStore(t, "rotlapse_")
	ctx := t.Context()
	refreshes := s.RefreshTokens()
	retry := requireRetryStore(t, refreshes)

	predecessor := newRotationToken("rt-lapse-predecessor", nil)
	if err := refreshes.Save(ctx, predecessor); err != nil {
		t.Fatalf("Save predecessor: %v", err)
	}
	if _, err := refreshes.Consume(ctx, predecessor.ID); err != nil {
		t.Fatalf("Consume predecessor: %v", err)
	}
	successor := newRotationToken("rt-lapse-successor", &predecessor.ID)
	successor.ExpiresAt = contract.Reference.Add(6 * time.Hour)
	sealed := []byte("sealed-lapse-response")
	if err := retry.SaveRotationWithRetry(ctx, successor, sealed); err != nil {
		t.Fatalf("SaveRotationWithRetry: %v", err)
	}

	// Inside the predecessor's lifetime the cached response is what the
	// grace window exists to deliver, so the bound must not truncate it
	// early.
	got, err := retry.LoadRetryResponse(ctx, predecessor.ID)
	if err != nil {
		t.Fatalf("LoadRetryResponse inside the predecessor's lifetime: %v", err)
	}
	if !bytes.Equal(got, sealed) {
		t.Fatalf("LoadRetryResponse = %q, want %q", got, sealed)
	}

	// One tick past the predecessor's expiry the response is gone, while
	// the successor it rotated to is untouched.
	clock.now = predecessor.ExpiresAt.Add(time.Nanosecond)
	if _, err := retry.LoadRetryResponse(ctx, predecessor.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("LoadRetryResponse past the predecessor's expiry = %v, want ErrNotFound", err)
	}
	if _, err := refreshes.Find(ctx, successor.ID); err != nil {
		t.Errorf("Find successor after the predecessor lapsed: %v", err)
	}
}

// TestRefreshRotation_TxCommitsSuccessorAndCacheTogether covers the
// same guarantee on the path where the token endpoint owns the
// transaction: both writes are buffered, so neither reaches the table
// before Commit and both are there afterwards. The predecessor is
// consumed inside the same transaction, which is what the refresh grant
// actually does, so this also pins that the cached response joins that
// staged write instead of overwriting it.
func TestRefreshRotation_TxCommitsSuccessorAndCacheTogether(t *testing.T) {
	t.Parallel()

	s := newIsolatedStore(t, "rottx_")
	ctx := t.Context()
	refreshes := s.RefreshTokens()
	outside := requireRetryStore(t, refreshes)

	predecessor := newRotationToken("rt-tx-predecessor", nil)
	if err := refreshes.Save(ctx, predecessor); err != nil {
		t.Fatalf("Save predecessor: %v", err)
	}

	tx, err := s.BeginTx(ctx)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.RefreshTokens().Consume(ctx, predecessor.ID); err != nil {
		t.Fatalf("tx Consume predecessor: %v", err)
	}
	successor := newRotationToken("rt-tx-successor", &predecessor.ID)
	sealed := []byte("sealed-tx-response")
	if err := requireRetryStore(t, tx.RefreshTokens()).SaveRotationWithRetry(ctx, successor, sealed); err != nil {
		t.Fatalf("tx SaveRotationWithRetry: %v", err)
	}

	if _, err := refreshes.Find(ctx, successor.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("uncommitted successor is visible outside the tx: %v", err)
	}
	if _, err := outside.LoadRetryResponse(ctx, predecessor.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("uncommitted retry response is visible outside the tx: %v", err)
	}

	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if _, err := refreshes.Find(ctx, successor.ID); err != nil {
		t.Fatalf("successor missing after Commit: %v", err)
	}
	got, err := outside.LoadRetryResponse(ctx, predecessor.ID)
	if err != nil {
		t.Fatalf("LoadRetryResponse after Commit: %v", err)
	}
	if !bytes.Equal(got, sealed) {
		t.Errorf("LoadRetryResponse = %q, want %q", got, sealed)
	}
	consumed, err := refreshes.Find(ctx, predecessor.ID)
	if err != nil {
		t.Fatalf("Find predecessor after Commit: %v", err)
	}
	if consumed.ConsumedAt == nil {
		t.Error("the cached response overwrote the consumed stamp the same transaction wrote")
	}
}
