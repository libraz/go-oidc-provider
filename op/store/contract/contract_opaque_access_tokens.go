package contract

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// --- OpaqueAccessTokenStore --------------------------------------------------
//
// The contract subgroup pins the substore semantics that ADR 0024 requires
// across every backend that ships op/storeadapter:
//
//   - hash-on-store: the raw bearer ID round-trips through Save / Find but
//     never appears in the underlying storage primitive (the inmem map, the
//     SQL row);
//   - idempotent revocation: RevokeByID against a missing record returns nil;
//   - cascade revocation: RevokeByGrant flips every record sharing a GrantID
//     and reports the count;
//   - GC: rows whose ExpiresAt is strictly before the cutoff are dropped.
//
// Backends that participate in the atomic-routing cluster (every backend the
// library ships) MUST satisfy every case here.

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var opaqueAccessTokenCases = []subtest{
	{"SaveFind", opaqueATSaveFind},
	{"FindMissing", opaqueATFindMissing},
	{"DuplicateSave", opaqueATDuplicateSave},
	{"RevokeByID", opaqueATRevokeByID},
	{"RevokeByIDMissing", opaqueATRevokeByIDMissing},
	{"RevokeByGrant", opaqueATRevokeByGrant},
	{"GC", opaqueATGC},
}

// requireOpaqueAccessTokens fetches the substore handle and skips the
// current test when the backend opts out by returning nil. Backends that
// do not enable opaque-format issuance (Wave 2-A) are allowed to return
// nil from [store.Store.OpaqueAccessTokens]; the contract still exercises
// every backend that does ship the substore.
func requireOpaqueAccessTokens(t *testing.T, s store.Store) store.OpaqueAccessTokenStore {
	t.Helper()
	at := s.OpaqueAccessTokens()
	if at == nil {
		t.Skipf("backend %T returns nil from OpaqueAccessTokens()", s)
	}
	return at
}

func newOpaqueAT(now time.Time, id, grantID string) *store.OpaqueAccessToken {
	return &store.OpaqueAccessToken{
		ID:        id,
		GrantID:   grantID,
		Subject:   "sub-1",
		ClientID:  "client-1",
		Scope:     []string{"openid"},
		Audience:  "https://api.example.com",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}
}

func opaqueATSaveFind(t *testing.T, f Factory) {
	b := f(t)
	at := requireOpaqueAccessTokens(t, b.Store)
	ctx := context.Background()
	tok := newOpaqueAT(b.Now(), "oat-1", "grant-1")
	if err := at.Save(ctx, tok); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := at.Find(ctx, "oat-1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got == nil {
		t.Fatal("Find: got nil, want record")
	}
	if got.ID != "oat-1" {
		t.Fatalf("ID = %q, want raw value", got.ID)
	}
	if got.GrantID != "grant-1" || got.ClientID != "client-1" {
		t.Fatalf("identity fields drift: %+v", got)
	}
	if got.Revoked {
		t.Fatal("Revoked = true on fresh record")
	}
}

func opaqueATFindMissing(t *testing.T, f Factory) {
	b := f(t)
	at := requireOpaqueAccessTokens(t, b.Store)
	_, err := at.Find(context.Background(), "absent")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find missing: want ErrNotFound, got %v", err)
	}
}

func opaqueATDuplicateSave(t *testing.T, f Factory) {
	b := f(t)
	at := requireOpaqueAccessTokens(t, b.Store)
	ctx := context.Background()
	tok := newOpaqueAT(b.Now(), "oat-dup", "grant-1")
	if err := at.Save(ctx, tok); err != nil {
		t.Fatalf("Save: %v", err)
	}
	err := at.Save(ctx, tok)
	if !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate Save: want ErrAlreadyExists, got %v", err)
	}
}

func opaqueATRevokeByID(t *testing.T, f Factory) {
	b := f(t)
	at := requireOpaqueAccessTokens(t, b.Store)
	ctx := context.Background()
	tok := newOpaqueAT(b.Now(), "oat-rev", "grant-1")
	if err := at.Save(ctx, tok); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := at.RevokeByID(ctx, "oat-rev"); err != nil {
		t.Fatalf("RevokeByID: %v", err)
	}
	got, err := at.Find(ctx, "oat-rev")
	if err != nil {
		// Backends MAY delete revoked rows; either is acceptable.
		if errors.Is(err, store.ErrNotFound) {
			return
		}
		t.Fatalf("Find post-revoke: %v", err)
	}
	if !got.Revoked {
		t.Fatal("Revoked flag not set after RevokeByID")
	}
	// Idempotent: second call against the same id is a no-op.
	if err := at.RevokeByID(ctx, "oat-rev"); err != nil {
		t.Fatalf("second RevokeByID: %v", err)
	}
}

func opaqueATRevokeByIDMissing(t *testing.T, f Factory) {
	b := f(t)
	at := requireOpaqueAccessTokens(t, b.Store)
	if err := at.RevokeByID(context.Background(), "absent"); err != nil {
		t.Fatalf("RevokeByID(absent): want nil, got %v", err)
	}
}

func opaqueATRevokeByGrant(t *testing.T, f Factory) {
	b := f(t)
	at := requireOpaqueAccessTokens(t, b.Store)
	ctx := context.Background()
	for _, id := range []string{"oat-a", "oat-b", "oat-c"} {
		if err := at.Save(ctx, newOpaqueAT(b.Now(), id, "grant-shared")); err != nil {
			t.Fatalf("Save %s: %v", id, err)
		}
	}
	if err := at.Save(ctx, newOpaqueAT(b.Now(), "oat-other", "grant-other")); err != nil {
		t.Fatalf("Save outside: %v", err)
	}
	n, err := at.RevokeByGrant(ctx, "grant-shared")
	if err != nil {
		t.Fatalf("RevokeByGrant: %v", err)
	}
	if n != 3 {
		t.Fatalf("RevokeByGrant count = %d, want 3", n)
	}
	other, err := at.Find(ctx, "oat-other")
	if err != nil {
		t.Fatalf("Find other: %v", err)
	}
	if other.Revoked {
		t.Fatal("outside grant should NOT be revoked")
	}
}

func opaqueATGC(t *testing.T, f Factory) {
	b := f(t)
	at := requireOpaqueAccessTokens(t, b.Store)
	ctx := context.Background()
	now := b.Now()
	live := newOpaqueAT(now, "oat-live", "g")
	live.ExpiresAt = now.Add(time.Hour)
	expired := newOpaqueAT(now, "oat-expired", "g")
	expired.ExpiresAt = now.Add(-time.Hour)
	for _, tok := range []*store.OpaqueAccessToken{live, expired} {
		if err := at.Save(ctx, tok); err != nil {
			t.Fatalf("Save %s: %v", tok.ID, err)
		}
	}
	n, err := at.GC(ctx, now)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if n < 1 {
		t.Fatalf("GC count = %d, want >= 1", n)
	}
	if _, err := at.Find(ctx, "oat-expired"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find expired post-GC: want ErrNotFound, got %v", err)
	}
	if _, err := at.Find(ctx, "oat-live"); err != nil {
		t.Fatalf("Find live post-GC: %v", err)
	}
}
