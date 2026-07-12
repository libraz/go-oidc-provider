package inmem_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func newRecoveryBatch(subject string) *store.RecoveryBatch {
	return &store.RecoveryBatch{
		Subject: subject,
		Codes: []store.RecoveryCode{
			{Hash: "$argon2id$v=19$m=65536,t=3,p=1$c2FsdAAAAAAAAAAA$aGFzaC0wMDAwMDAwMDAwMDAwMDAwMDAwMA"},
			{Hash: "$argon2id$v=19$m=65536,t=3,p=1$c2FsdAAAAAAAAAAA$aGFzaC0xMTExMTExMTExMTExMTExMTExMQ"},
		},
		GeneratedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
}

func TestRecoveryStore_PutGetRoundTrip(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	rs := s.RecoveryCodes()
	ctx := context.Background()

	b := newRecoveryBatch("user-alice")
	if err := rs.Put(ctx, b); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := rs.Get(ctx, "user-alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Subject != b.Subject {
		t.Errorf("Subject=%q want %q", got.Subject, b.Subject)
	}
	if len(got.Codes) != len(b.Codes) {
		t.Fatalf("len(Codes)=%d want %d", len(got.Codes), len(b.Codes))
	}
	for i := range b.Codes {
		if got.Codes[i].Hash != b.Codes[i].Hash {
			t.Errorf("Codes[%d].Hash=%q want %q", i, got.Codes[i].Hash, b.Codes[i].Hash)
		}
	}
	if !got.GeneratedAt.Equal(b.GeneratedAt) {
		t.Errorf("GeneratedAt=%v want %v", got.GeneratedAt, b.GeneratedAt)
	}
}

func TestRecoveryStore_GetNotFound(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	if _, err := s.RecoveryCodes().Get(context.Background(), "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err=%v want ErrNotFound", err)
	}
}

func TestRecoveryStore_PutOverwrites(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	rs := s.RecoveryCodes()
	ctx := context.Background()

	first := newRecoveryBatch("user-alice")
	if err := rs.Put(ctx, first); err != nil {
		t.Fatalf("Put first: %v", err)
	}
	second := newRecoveryBatch("user-alice")
	second.Codes = []store.RecoveryCode{
		{Hash: "$argon2id$v=19$m=65536,t=3,p=1$c2FsdAAAAAAAAAAA$aGFzaC1hYWFhYWFhYWFhYWFhYWFhYWFhYQ"},
	}
	if err := rs.Put(ctx, second); err != nil {
		t.Fatalf("Put second: %v", err)
	}
	got, err := rs.Get(ctx, "user-alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Codes) != 1 {
		t.Errorf("len(Codes)=%d want 1 (overwrite did not stick)", len(got.Codes))
	}
}

func TestRecoveryStore_DeleteRemovesBatch(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	rs := s.RecoveryCodes()
	ctx := context.Background()

	b := newRecoveryBatch("user-alice")
	if err := rs.Put(ctx, b); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := rs.Delete(ctx, "user-alice"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := rs.Get(ctx, "user-alice"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Get after Delete: err=%v want ErrNotFound", err)
	}
}

func TestRecoveryStore_DeleteMissingReturnsNotFound(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	if err := s.RecoveryCodes().Delete(context.Background(), "nobody"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err=%v want ErrNotFound", err)
	}
}

func TestRecoveryStore_PutNilRejected(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	if err := s.RecoveryCodes().Put(context.Background(), nil); err == nil {
		t.Error("Put(nil) returned nil error")
	}
}

func TestRecoveryStore_GetClonesBatch(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	rs := s.RecoveryCodes()
	ctx := context.Background()

	b := newRecoveryBatch("user-alice")
	if err := rs.Put(ctx, b); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := rs.Get(ctx, "user-alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	// Mutating the returned batch MUST NOT bleed into the store.
	got.Codes[0].Hash = "tampered"
	got.Codes[0].ConsumedAt = time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)

	again, err := rs.Get(ctx, "user-alice")
	if err != nil {
		t.Fatalf("Get again: %v", err)
	}
	if again.Codes[0].Hash == "tampered" {
		t.Errorf("Codes[0].Hash leak: caller mutation bled into store")
	}
	if !again.Codes[0].ConsumedAt.IsZero() {
		t.Errorf("Codes[0].ConsumedAt=%v want zero (caller mutation leaked)", again.Codes[0].ConsumedAt)
	}
}

func TestRecoveryStore_PutClonesBatch(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	rs := s.RecoveryCodes()
	ctx := context.Background()

	b := newRecoveryBatch("user-alice")
	if err := rs.Put(ctx, b); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// Mutate the original after Put — the store MUST hold an
	// independent copy.
	b.Codes[0].Hash = "tampered"

	got, err := rs.Get(ctx, "user-alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Codes[0].Hash == "tampered" {
		t.Errorf("post-Put mutation of caller batch leaked into store")
	}
}

// TestRecoveryStore_ConsumeRejectsStaleHashAfterRegenerate pins #19: a
// recovery code from a batch that was regenerated between Get and Consume
// MUST NOT redeem a slot of the new batch. Regenerating is exactly how a
// user revokes leaked codes, so honouring the stale hash would be a
// revocation bypass.
func TestRecoveryStore_ConsumeRejectsStaleHashAfterRegenerate(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	rs := s.RecoveryCodes()
	ctx := context.Background()

	// Original batch the attacker holds a code from.
	stale := newRecoveryBatch("user-alice")
	if err := rs.Put(ctx, stale); err != nil {
		t.Fatalf("Put stale: %v", err)
	}
	// User regenerates: a fresh batch with different hashes replaces it.
	fresh := newRecoveryBatch("user-alice")
	fresh.Codes = []store.RecoveryCode{
		{Hash: "$argon2id$v=19$m=65536,t=3,p=1$c2FsdAAAAAAAAAAA$aGFzaC1mcmVzaDAwMDAwMDAwMDAwMDAwMDAwMA"},
		{Hash: "$argon2id$v=19$m=65536,t=3,p=1$c2FsdAAAAAAAAAAA$aGFzaC1mcmVzaDExMTExMTExMTExMTExMTExMQ"},
	}
	if err := rs.Put(ctx, fresh); err != nil {
		t.Fatalf("Put fresh: %v", err)
	}

	// Consuming with the stale batch's code MUST be rejected.
	consumed := *stale
	consumed.Codes = append([]store.RecoveryCode(nil), stale.Codes...)
	consumed.Codes[0].ConsumedAt = time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	if err := rs.Consume(ctx, &consumed, 0); !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Fatalf("Consume with stale hash: want ErrAlreadyConsumed, got %v", err)
	}

	// The fresh batch's slot 0 must remain unconsumed.
	got, err := rs.Get(ctx, "user-alice")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !got.Codes[0].ConsumedAt.IsZero() {
		t.Error("stale code burned a slot of the regenerated batch (revocation bypass)")
	}
}

func TestRecoveryStore_ConsumeRaceSingleWinner(t *testing.T) {
	t.Parallel()

	s := inmem.New()
	rs := s.RecoveryCodes()
	ctx := context.Background()
	batch := newRecoveryBatch("user-alice")
	if err := rs.Put(ctx, batch); err != nil {
		t.Fatalf("Put: %v", err)
	}
	consumed := *batch
	consumed.Codes = append([]store.RecoveryCode(nil), batch.Codes...)
	consumed.Codes[0].ConsumedAt = time.Now().UTC()

	var wins atomic.Int64
	var wg sync.WaitGroup
	for range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := rs.Consume(ctx, &consumed, 0)
			switch {
			case err == nil:
				wins.Add(1)
			case errors.Is(err, store.ErrAlreadyConsumed):
			default:
				t.Errorf("Consume: %v", err)
			}
		}()
	}
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("Consume wins=%d want 1", got)
	}
	got, err := rs.Get(ctx, batch.Subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Codes[0].ConsumedAt.IsZero() {
		t.Fatal("ConsumedAt was not persisted")
	}
}
