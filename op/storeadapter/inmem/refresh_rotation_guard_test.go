package inmem_test

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func strPtr(s string) *string { return &s }

// newGuardRefresh builds a refresh-token record with a far-future
// expiry so the expiry gate never masks the rotation-guard behaviour the
// tests exercise.
func newGuardRefresh(now time.Time, id string, parent *string) *store.RefreshToken {
	return &store.RefreshToken{
		ID:        id,
		ClientID:  "c",
		Subject:   "s",
		GrantID:   "g",
		Scope:     []string{"openid", "offline_access"},
		ParentID:  parent,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}
}

// TestRefreshRotation_HappyPath pins the single-threaded rotation
// contract the OFCS suite depends on: rotate R -> R', R is consumed, and
// R' is a live, consumable token. The rotation-guard hardening must not
// perturb this path.
func TestRefreshRotation_HappyPath(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()
	rt := s.RefreshTokens()

	if err := rt.Save(ctx, newGuardRefresh(now, "R", nil)); err != nil {
		t.Fatalf("Save R: %v", err)
	}
	consumed, err := rt.Consume(ctx, "R")
	if err != nil {
		t.Fatalf("Consume R: %v", err)
	}
	if consumed.ConsumedAt == nil {
		t.Fatal("Consume R returned nil ConsumedAt")
	}
	if consumed.Revoked {
		t.Fatal("legitimate rotation must not mark the parent Revoked")
	}

	if err := rt.Save(ctx, newGuardRefresh(now, "R2", strPtr("R"))); err != nil {
		t.Fatalf("Save rotated R2: %v", err)
	}
	got, err := rt.Find(ctx, "R2")
	if err != nil {
		t.Fatalf("Find R2: %v", err)
	}
	if got.ConsumedAt != nil || got.Revoked {
		t.Fatalf("rotated R2 must be live after happy-path rotation: %+v", got)
	}
	if _, err := rt.Consume(ctx, "R2"); err != nil {
		t.Fatalf("Consume rotated R2: %v", err)
	}
}

// TestRefreshRotation_SaveAfterRevokeIsDead exercises the revoke-then-save
// ordering: a chain revocation lands before the racing rotation's Save.
// The single-critical-section guard must stamp the rotated descendant
// consumed + revoked so it never becomes redeemable (RFC 9700 §2.2.2).
func TestRefreshRotation_SaveAfterRevokeIsDead(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()
	rt := s.RefreshTokens()

	if err := rt.Save(ctx, newGuardRefresh(now, "R", nil)); err != nil {
		t.Fatalf("Save R: %v", err)
	}
	if _, err := rt.Consume(ctx, "R"); err != nil {
		t.Fatalf("Consume R: %v", err)
	}
	// Replay cascade revokes the chain before the rotation persists R'.
	if err := rt.RevokeChain(ctx, "R"); err != nil {
		t.Fatalf("RevokeChain R: %v", err)
	}
	if err := rt.Save(ctx, newGuardRefresh(now, "R2", strPtr("R"))); err != nil {
		t.Fatalf("Save rotated R2: %v", err)
	}
	got, err := rt.Find(ctx, "R2")
	if err != nil {
		t.Fatalf("Find R2: %v", err)
	}
	if got.ConsumedAt == nil || !got.Revoked {
		t.Fatalf("R2 saved under a revoked parent must be dead: %+v", got)
	}
	if _, err := rt.Consume(ctx, "R2"); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Consume R2 err=%v, want ErrAlreadyConsumed", err)
	}
}

// TestRefreshRotation_RevokeAfterSaveIsDead exercises the save-then-revoke
// ordering: the rotation persists R' first, then the chain revocation
// runs. The BFS walk must reach the freshly persisted descendant through
// its parent pointer and revoke it.
func TestRefreshRotation_RevokeAfterSaveIsDead(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	s := inmem.New(inmem.WithClock(fakeClock{now: now}))
	ctx := context.Background()
	rt := s.RefreshTokens()

	if err := rt.Save(ctx, newGuardRefresh(now, "R", nil)); err != nil {
		t.Fatalf("Save R: %v", err)
	}
	if _, err := rt.Consume(ctx, "R"); err != nil {
		t.Fatalf("Consume R: %v", err)
	}
	if err := rt.Save(ctx, newGuardRefresh(now, "R2", strPtr("R"))); err != nil {
		t.Fatalf("Save rotated R2: %v", err)
	}
	// Replay cascade runs after the rotation has persisted R'.
	if err := rt.RevokeChain(ctx, "R"); err != nil {
		t.Fatalf("RevokeChain R: %v", err)
	}
	got, err := rt.Find(ctx, "R2")
	if err != nil {
		t.Fatalf("Find R2: %v", err)
	}
	if got.ConsumedAt == nil || !got.Revoked {
		t.Fatalf("R2 must be revoked by the chain walk: %+v", got)
	}
}

// TestRefreshRotation_ConcurrentReplayRevokesRotatedChain is the -race
// sentinel for the replay-revocation TOCTOU. Across many iterations two
// goroutines contend for the same token: exactly one wins the Consume and
// rotates (Save R'), the other observes replay and revokes the chain. No
// matter which side wins the race, the rotated descendant MUST end up
// revoked and unusable (RFC 9700 §2.2.2).
func TestRefreshRotation_ConcurrentReplayRevokesRotatedChain(t *testing.T) {
	t.Parallel()
	now := contract.Reference
	const iterations = 300

	for i := range iterations {
		s := inmem.New(inmem.WithClock(fakeClock{now: now}))
		ctx := context.Background()
		rt := s.RefreshTokens()
		if err := rt.Save(ctx, newGuardRefresh(now, "R", nil)); err != nil {
			t.Fatalf("iter %d: Save R: %v", i, err)
		}
		rotatedID := "R2-" + strconv.Itoa(i)

		var wg sync.WaitGroup
		var rotated bool
		var saveErr, revokeErr error
		attempt := func() {
			defer wg.Done()
			if _, err := rt.Consume(ctx, "R"); err != nil {
				// Lost the consume race: act as the replay detector.
				if e := rt.RevokeChain(ctx, "R"); e != nil {
					revokeErr = e
				}
				return
			}
			// Won the consume race: rotate.
			rotated = true
			saveErr = rt.Save(ctx, newGuardRefresh(now, rotatedID, strPtr("R")))
		}
		wg.Add(2)
		go attempt()
		go attempt()
		wg.Wait()

		if revokeErr != nil {
			t.Fatalf("iter %d: RevokeChain: %v", i, revokeErr)
		}
		if !rotated {
			t.Fatalf("iter %d: no goroutine won the consume race", i)
		}
		if saveErr != nil {
			t.Fatalf("iter %d: Save rotated: %v", i, saveErr)
		}
		got, err := rt.Find(ctx, rotatedID)
		if err != nil {
			t.Fatalf("iter %d: Find rotated: %v", i, err)
		}
		if got.ConsumedAt == nil || !got.Revoked {
			t.Fatalf("iter %d: rotated descendant survived the replay race: %+v", i, got)
		}
		if _, err := rt.Consume(ctx, rotatedID); !errors.Is(err, store.ErrAlreadyConsumed) {
			t.Fatalf("iter %d: rotated descendant still consumable: err=%v", i, err)
		}
	}
}
