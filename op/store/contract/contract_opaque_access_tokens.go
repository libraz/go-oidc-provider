package contract

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// --- OpaqueAccessTokenStore --------------------------------------------------
//
// The contract subgroup pins the substore semantics that requires
// across every backend that ships op/storeadapter:
//
//   - hash-on-store: the raw bearer ID round-trips through Save / Find but
//     never appears in the underlying storage primitive (the inmem map, the
//     SQL row);
//   - idempotent revocation: RevokeByID against a missing record returns nil;
//   - cascade revocation: RevokeByGrant flips every record sharing a GrantID
//     and reports the count;
//   - chain revocation: a backend implementing
//     [store.OpaqueAccessTokenChainRevoker] round-trips ChainID and its
//     RevokeByChain flips only the records of that grant and chain;
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
	{"RevokeByChain", opaqueATRevokeByChain},
	{"GC", opaqueATGC},
}

// requireOpaqueAccessTokens fetches the substore handle and skips the
// current test when the backend opts out by returning nil. Backends
// that do not enable opaque-format issuance are allowed to return nil
// from [store.Store.OpaqueAccessTokens]; the contract still exercises
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
	tok.AuthorizationDetails = []map[string]any{{"type": "payment", "amount": "100"}}
	tok.Claims = recordedClaimsRequest()
	tok.AuthorizationRecorded = true
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
	// The per-authorization state round-trips, or a backend drops all of
	// it with its marker; a partial round-trip is a defect.
	if got.AuthorizationRecorded {
		if !reflect.DeepEqual(got.AuthorizationDetails, tok.AuthorizationDetails) ||
			!reflect.DeepEqual(got.Claims, tok.Claims) {
			t.Fatalf("authorization state mismatch: details=%v claims=%v", got.AuthorizationDetails, got.Claims)
		}
	} else if len(got.AuthorizationDetails) != 0 || len(got.Claims) != 0 {
		t.Fatalf("unrecorded row carries details=%v claims=%v", got.AuthorizationDetails, got.Claims)
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

func opaqueATRevokeByChain(t *testing.T, f Factory) {
	b := f(t)
	at := requireOpaqueAccessTokens(t, b.Store)
	chains, ok := at.(store.OpaqueAccessTokenChainRevoker)
	if !ok {
		t.Skipf("backend %T does not implement store.OpaqueAccessTokenChainRevoker", at)
	}
	ctx := context.Background()
	rows := seedChainedOpaqueATs(t, at, b.Now())
	if got, err := at.Find(ctx, "oat-chain-a1"); err != nil || got.ChainID != "chain-a" {
		t.Fatalf("Find ChainID = %+v, %v; want chain-a", got, err)
	}
	if n, err := chains.RevokeByChain(ctx, "grant-shared", ""); err != nil || n != 0 {
		t.Fatalf("RevokeByChain with empty chain = %d, %v; want 0, nil", n, err)
	}
	n, err := chains.RevokeByChain(ctx, "grant-shared", "chain-a")
	if err != nil {
		t.Fatalf("RevokeByChain: %v", err)
	}
	if n != 2 {
		t.Fatalf("RevokeByChain count = %d, want 2", n)
	}
	for _, r := range rows {
		got, err := at.Find(ctx, r.id)
		if err != nil {
			t.Fatalf("Find %s: %v", r.id, err)
		}
		want := r.grantID == "grant-shared" && r.chainID == "chain-a"
		if got.Revoked != want {
			t.Fatalf("%s Revoked=%v want %v", r.id, got.Revoked, want)
		}
	}
}

// chainedOpaqueAT is one row [opaqueATRevokeByChain] seeds.
type chainedOpaqueAT struct{ id, grantID, chainID string }

// seedChainedOpaqueATs saves two chains under one grant, a chainless row
// under it, and a same-named chain under another grant.
func seedChainedOpaqueATs(t *testing.T, at store.OpaqueAccessTokenStore, now time.Time) []chainedOpaqueAT {
	t.Helper()
	rows := []chainedOpaqueAT{
		{"oat-chain-a1", "grant-shared", "chain-a"},
		{"oat-chain-a2", "grant-shared", "chain-a"},
		{"oat-chain-b", "grant-shared", "chain-b"},
		{"oat-chainless", "grant-shared", ""},
		{"oat-chain-a-other-grant", "grant-other", "chain-a"},
	}
	for _, r := range rows {
		tok := newOpaqueAT(now, r.id, r.grantID)
		tok.ChainID = r.chainID
		if err := at.Save(context.Background(), tok); err != nil {
			t.Fatalf("Save %s: %v", r.id, err)
		}
	}
	return rows
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
