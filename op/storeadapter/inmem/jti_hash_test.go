package inmem //nolint:testpackage // touches package-private map fields to assert the hash-on-store invariant.

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// TestConsumedJTIs_HashesRawValueOnStore pins the H-G2 invariant: a
// raw "jti" handed to Mark must never appear verbatim as a map key.
// The store keys on the SHA-256 digest so a heap dump or memory leak
// reveals only one-way digests, matching the redis adapter's posture.
func TestConsumedJTIs_HashesRawValueOnStore(t *testing.T) {
	t.Parallel()

	s := New()
	const raw = "raw-jti-value-1234567890"
	expires := time.Now().Add(time.Hour)
	if err := s.ConsumedJTIs().Mark(context.Background(), raw, expires); err != nil {
		t.Fatalf("Mark: %v", err)
	}

	digest := patterns.Digest(raw)
	js := s.jtis
	js.mu.RLock()
	defer js.mu.RUnlock()
	if _, ok := js.m[raw]; ok {
		t.Errorf("raw jti %q present as map key — must be hashed", raw)
	}
	if _, ok := js.m[digest]; !ok {
		t.Errorf("digest %q absent from map — Mark did not hash", digest)
	}
}

// TestConsumedJTIs_HasMatchesRawAfterHash confirms Has round-trips
// through the same digest helper Mark used.
func TestConsumedJTIs_HasMatchesRawAfterHash(t *testing.T) {
	t.Parallel()

	s := New()
	const raw = "another-raw-jti"
	if err := s.ConsumedJTIs().Mark(context.Background(), raw, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Mark: %v", err)
	}
	got, err := s.ConsumedJTIs().Has(context.Background(), raw)
	if err != nil {
		t.Fatalf("Has: %v", err)
	}
	if !got {
		t.Errorf("Has returned false for jti just marked")
	}
}

// TestConsumedJTIs_DuplicateMarkSurfacesAlreadyConsumed verifies the
// digest-keyed map still honours the contract's first-writer-wins rule.
func TestConsumedJTIs_DuplicateMarkSurfacesAlreadyConsumed(t *testing.T) {
	t.Parallel()

	s := New()
	const raw = "dup-jti"
	exp := time.Now().Add(time.Hour)
	if err := s.ConsumedJTIs().Mark(context.Background(), raw, exp); err != nil {
		t.Fatalf("first Mark: %v", err)
	}
	err := s.ConsumedJTIs().Mark(context.Background(), raw, exp)
	if !errors.Is(err, store.ErrAlreadyConsumed) {
		t.Errorf("second Mark err=%v want ErrAlreadyConsumed", err)
	}
}

func TestConsumedJTIs_MarkAmortizesExpiredSweep(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)
	clk := &parTestClock{now: now}
	s := New(WithClock(clk))
	ctx := context.Background()

	if err := s.ConsumedJTIs().Mark(ctx, "expired-jti", now.Add(-time.Second)); err != nil {
		t.Fatalf("Mark expired: %v", err)
	}
	if len(s.jtis.m) != 1 {
		t.Fatalf("after first Mark len=%d want 1", len(s.jtis.m))
	}
	for i := uint32(1); i < jtiFullGCMarkInterval; i++ {
		if err := s.ConsumedJTIs().Mark(ctx, "fresh-jti-"+strconv.Itoa(int(i)), now.Add(time.Minute)); err != nil {
			t.Fatalf("Mark fresh #%d: %v", i, err)
		}
	}
	if _, exists := s.jtis.m[patterns.Digest("expired-jti")]; exists {
		t.Fatal("expired JTI survived the amortized full sweep")
	}
	if s.jtis.marksSinceGC != 0 {
		t.Fatalf("marksSinceGC=%d want 0 after sweep", s.jtis.marksSinceGC)
	}
}
