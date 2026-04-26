package inmem_test

import (
	"context"
	"errors"
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
