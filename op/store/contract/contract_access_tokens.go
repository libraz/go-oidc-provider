package contract

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// The JTI registry is the shadow of every issued JWT access token, and
// the userinfo, introspection, and revocation endpoints all decide
// against it. Its contract has two shapes that are easy to get subtly
// wrong on a backend that is not a relational database:
//
//   - "absent" is spelled either (nil, nil) or ErrNotFound, and both
//     are permitted, so a caller must not distinguish them.
//   - RevokeByJTI is idempotent and silent about a missing record,
//     mirroring RFC 7009 §2.2: the revocation endpoint answers 200
//     either way, so the substore has nothing to report.
//
// GC is the third: the cutoff is strictly-before, so a record expiring
// exactly at the sweep instant survives it.

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var accessTokenRegistryCases = []subtest{
	{"RegisterFindRoundTrip", accessTokenRoundTrip},
	{"FindMissing", accessTokenFindMissing},
	{"RegisterDuplicate", accessTokenRegisterDuplicate},
	{"RevokeByJTIRetiresRecord", accessTokenRevokeByJTI},
	{"RevokeByJTIIsIdempotent", accessTokenRevokeByJTIIdempotent},
	{"RevokeByJTIMissingIsNotAnError", accessTokenRevokeByJTIMissing},
	{"RevokeByGrantCountsRows", accessTokenRevokeByGrant},
	{"RevokeByGrantMissingCountsZero", accessTokenRevokeByGrantMissing},
	{"GCDropsRecordsExpiredBeforeCutoff", accessTokenGC},
	{"GCLeavesRecordsExpiringAtCutoff", accessTokenGCBoundary},
}

func requireAccessTokens(t *testing.T, s store.Store) store.AccessTokenRegistry {
	t.Helper()
	registry := s.AccessTokens()
	if registry == nil {
		t.Skipf("backend %T returns nil from AccessTokens()", s)
	}
	return registry
}

// findAccessToken normalises the two permitted spellings of "absent" so
// the sub-tests can assert on presence without caring which one the
// backend chose.
func findAccessToken(
	t *testing.T,
	registry store.AccessTokenRegistry,
	jti string,
) (*store.AccessTokenRecord, bool) {
	t.Helper()
	rec, err := registry.Find(context.Background(), jti)
	if errors.Is(err, store.ErrNotFound) {
		return nil, false
	}
	if err != nil {
		t.Fatalf("Find(%q): %v", jti, err)
	}
	if rec == nil {
		return nil, false
	}
	return rec, true
}

func newAccessTokenRecord(now time.Time, jti, grantID string) store.AccessTokenRecord {
	return store.AccessTokenRecord{
		JTI:       jti,
		GrantID:   grantID,
		Subject:   "sub",
		ClientID:  "client",
		Scopes:    []string{"openid", "profile"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}
}

func accessTokenRoundTrip(t *testing.T, f Factory) {
	b := f(t)
	registry := requireAccessTokens(t, b.Store)
	want := newAccessTokenRecord(b.Now(), "at-round-trip", "grant-1")
	if err := registry.Register(context.Background(), want); err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, ok := findAccessToken(t, registry, want.JTI)
	if !ok {
		t.Fatal("Find after Register reported the record absent")
	}
	if got.JTI != want.JTI || got.GrantID != want.GrantID {
		t.Fatalf("identity = (%q, %q), want (%q, %q)", got.JTI, got.GrantID, want.JTI, want.GrantID)
	}
	if got.Subject != want.Subject || got.ClientID != want.ClientID {
		t.Fatalf("record = %+v, want subject/client of %+v", got, want)
	}
	if !slices.Equal(got.Scopes, want.Scopes) {
		t.Fatalf("Scopes = %v, want %v", got.Scopes, want.Scopes)
	}
	if !got.IssuedAt.Equal(want.IssuedAt) {
		t.Fatalf("IssuedAt = %v, want %v", got.IssuedAt, want.IssuedAt)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Fatalf("ExpiresAt = %v, want %v", got.ExpiresAt, want.ExpiresAt)
	}
	if got.Revoked {
		t.Fatal("freshly registered record is marked revoked")
	}
}

func accessTokenFindMissing(t *testing.T, f Factory) {
	b := f(t)
	registry := requireAccessTokens(t, b.Store)
	if _, ok := findAccessToken(t, registry, "at-absent"); ok {
		t.Fatal("Find returned a record for an unregistered jti")
	}
}

func accessTokenRegisterDuplicate(t *testing.T, f Factory) {
	b := f(t)
	registry := requireAccessTokens(t, b.Store)
	ctx := context.Background()
	rec := newAccessTokenRecord(b.Now(), "at-dup", "grant-1")
	if err := registry.Register(ctx, rec); err != nil {
		t.Fatalf("Register: %v", err)
	}
	// A colliding jti is reachable only through an implementation bug,
	// so the registry must refuse rather than silently overwrite the
	// record a live token depends on.
	if err := registry.Register(ctx, rec); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("duplicate Register: want ErrAlreadyExists, got %v", err)
	}
}

func accessTokenRevokeByJTI(t *testing.T, f Factory) {
	b := f(t)
	registry := requireAccessTokens(t, b.Store)
	ctx := context.Background()
	rec := newAccessTokenRecord(b.Now(), "at-revoke", "grant-1")
	if err := registry.Register(ctx, rec); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := registry.RevokeByJTI(ctx, rec.JTI); err != nil {
		t.Fatalf("RevokeByJTI: %v", err)
	}
	// A retired entry may be reported either as absent or as a record
	// carrying Revoked; both satisfy the contract.
	if got, ok := findAccessToken(t, registry, rec.JTI); ok && !got.Revoked {
		t.Fatalf("record after RevokeByJTI = %+v, want absent or Revoked", got)
	}
}

func accessTokenRevokeByJTIIdempotent(t *testing.T, f Factory) {
	b := f(t)
	registry := requireAccessTokens(t, b.Store)
	ctx := context.Background()
	rec := newAccessTokenRecord(b.Now(), "at-revoke-twice", "grant-1")
	if err := registry.Register(ctx, rec); err != nil {
		t.Fatalf("Register: %v", err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if err := registry.RevokeByJTI(ctx, rec.JTI); err != nil {
			t.Fatalf("RevokeByJTI attempt %d: %v", attempt, err)
		}
	}
}

func accessTokenRevokeByJTIMissing(t *testing.T, f Factory) {
	b := f(t)
	registry := requireAccessTokens(t, b.Store)
	// RFC 7009 §2.2: the revocation endpoint answers 200 for a token it
	// does not know, so the substore reports nothing either.
	if err := registry.RevokeByJTI(context.Background(), "at-absent"); err != nil {
		t.Fatalf("RevokeByJTI(absent): want nil, got %v", err)
	}
}

func accessTokenRevokeByGrant(t *testing.T, f Factory) {
	b := f(t)
	registry := requireAccessTokens(t, b.Store)
	ctx := context.Background()
	for _, jti := range []string{"at-g1", "at-g2", "at-g3"} {
		if err := registry.Register(ctx, newAccessTokenRecord(b.Now(), jti, "grant-shared")); err != nil {
			t.Fatalf("Register %s: %v", jti, err)
		}
	}
	other := newAccessTokenRecord(b.Now(), "at-other", "grant-other")
	if err := registry.Register(ctx, other); err != nil {
		t.Fatalf("Register other: %v", err)
	}

	n, err := registry.RevokeByGrant(ctx, "grant-shared")
	if err != nil {
		t.Fatalf("RevokeByGrant: %v", err)
	}
	if n != 3 {
		t.Fatalf("RevokeByGrant count = %d, want 3", n)
	}
	for _, jti := range []string{"at-g1", "at-g2", "at-g3"} {
		if got, ok := findAccessToken(t, registry, jti); ok && !got.Revoked {
			t.Fatalf("%s survived the cascade: %+v", jti, got)
		}
	}
	// The cascade is scoped to one grant.
	got, ok := findAccessToken(t, registry, other.JTI)
	if !ok {
		t.Fatal("cascade removed a record belonging to another grant")
	}
	if got.Revoked {
		t.Fatal("cascade revoked a record belonging to another grant")
	}
}

func accessTokenRevokeByGrantMissing(t *testing.T, f Factory) {
	b := f(t)
	registry := requireAccessTokens(t, b.Store)
	n, err := registry.RevokeByGrant(context.Background(), "grant-absent")
	if err != nil {
		t.Fatalf("RevokeByGrant(absent): want nil error, got %v", err)
	}
	if n != 0 {
		t.Fatalf("RevokeByGrant(absent) count = %d, want 0", n)
	}
}

func accessTokenGC(t *testing.T, f Factory) {
	b := f(t)
	registry := requireAccessTokens(t, b.Store)
	ctx := context.Background()
	now := b.Now()

	expired := newAccessTokenRecord(now, "at-gc-expired", "grant-1")
	expired.ExpiresAt = now.Add(-time.Hour)
	if err := registry.Register(ctx, expired); err != nil {
		t.Fatalf("Register expired: %v", err)
	}
	live := newAccessTokenRecord(now, "at-gc-live", "grant-1")
	if err := registry.Register(ctx, live); err != nil {
		t.Fatalf("Register live: %v", err)
	}

	n, err := registry.GC(ctx, now)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if n != 1 {
		t.Fatalf("GC removed %d records, want 1", n)
	}
	if _, ok := findAccessToken(t, registry, expired.JTI); ok {
		t.Fatal("GC left an expired record behind")
	}
	if _, ok := findAccessToken(t, registry, live.JTI); !ok {
		t.Fatal("GC removed a live record")
	}
}

func accessTokenGCBoundary(t *testing.T, f Factory) {
	b := f(t)
	registry := requireAccessTokens(t, b.Store)
	ctx := context.Background()
	now := b.Now()

	// The cutoff is strictly-before: a record expiring exactly at the
	// sweep instant is still within its lifetime and survives.
	atCutoff := newAccessTokenRecord(now, "at-gc-boundary", "grant-1")
	atCutoff.ExpiresAt = now
	if err := registry.Register(ctx, atCutoff); err != nil {
		t.Fatalf("Register: %v", err)
	}
	n, err := registry.GC(ctx, now)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if n != 0 {
		t.Fatalf("GC removed %d records at the cutoff instant, want 0", n)
	}
	if _, ok := findAccessToken(t, registry, atCutoff.JTI); !ok {
		t.Fatal("GC removed a record expiring exactly at the cutoff")
	}
}
