package inmem_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestOpaqueAccessToken_RoundTrip locks in the happy path: a freshly
// saved record is reachable via Find with every metadata field intact,
// and the raw ID survives the round-trip even though the stored row
// only carries the digest.
func TestOpaqueAccessToken_RoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	authTime := time.Date(2026, 4, 29, 11, 55, 0, 0, time.UTC)
	tok := &store.OpaqueAccessToken{
		ID:                 "raw-opaque-id-1",
		GrantID:            "grant-1",
		Subject:            "user-1",
		ClientID:           "client-1",
		Scope:              []string{"openid", "profile"},
		Audience:           "https://api.example.com",
		ACR:                "urn:mace:incommon:iap:silver",
		AMR:                []string{"pwd", "otp"},
		AuthTime:           authTime,
		DPoPJKT:            "dpop-thumb",
		MTLSCertThumbprint: "",
		IssuedAt:           time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC),
		ExpiresAt:          time.Date(2026, 4, 29, 12, 5, 0, 0, time.UTC),
	}
	if err := s.OpaqueAccessTokens().Save(ctx, tok); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := s.OpaqueAccessTokens().Find(ctx, "raw-opaque-id-1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got == nil {
		t.Fatal("Find: got nil, want record")
	}
	if got.ID != "raw-opaque-id-1" {
		t.Errorf("ID = %q, want raw value back", got.ID)
	}
	if got.GrantID != "grant-1" || got.Subject != "user-1" || got.ClientID != "client-1" {
		t.Errorf("identity fields: %+v", got)
	}
	if got.Audience != "https://api.example.com" {
		t.Errorf("Audience = %q", got.Audience)
	}
	if got.ACR != "urn:mace:incommon:iap:silver" {
		t.Errorf("ACR = %q", got.ACR)
	}
	if !reflect.DeepEqual(got.AMR, []string{"pwd", "otp"}) {
		t.Errorf("AMR = %v", got.AMR)
	}
	if !got.AuthTime.Equal(authTime) {
		t.Errorf("AuthTime = %v, want %v", got.AuthTime, authTime)
	}
	if got.DPoPJKT != "dpop-thumb" {
		t.Errorf("DPoPJKT = %q", got.DPoPJKT)
	}
	if got.MTLSCertThumbprint != "" {
		t.Errorf("MTLSCertThumbprint = %q, want empty", got.MTLSCertThumbprint)
	}
	if got.Revoked {
		t.Errorf("Revoked = true on fresh record")
	}
	if !reflect.DeepEqual(got.Scope, []string{"openid", "profile"}) {
		t.Errorf("Scope = %v", got.Scope)
	}
}

// TestOpaqueAccessToken_FindMissing locks in the (nil, ErrNotFound) absent
// shape per the substore contract.
func TestOpaqueAccessToken_FindMissing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	got, err := s.OpaqueAccessTokens().Find(ctx, "no-such-id")
	if !errors.Is(err, store.ErrNotFound) {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
	if got != nil {
		t.Errorf("rec = %+v, want nil", got)
	}
	// Empty id is also absent.
	if _, err := s.OpaqueAccessTokens().Find(ctx, ""); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Find(\"\") err = %v, want ErrNotFound", err)
	}
}

// TestOpaqueAccessToken_Save_Duplicate confirms Save surfaces
// ErrAlreadyExists rather than silently overwriting an existing row.
// 256-bit ID entropy keeps the duplicate path reachable only by
// implementation bugs; surfacing a typed error lets the token endpoint
// refuse to issue a wire token whose shadow row is in an unexpected
// state.
func TestOpaqueAccessToken_Save_Duplicate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	tok := &store.OpaqueAccessToken{
		ID:        "dup",
		ClientID:  "client-1",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.OpaqueAccessTokens().Save(ctx, tok); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	if err := s.OpaqueAccessTokens().Save(ctx, tok); !errors.Is(err, store.ErrAlreadyExists) {
		t.Errorf("second Save: err = %v, want ErrAlreadyExists", err)
	}
}

// TestOpaqueAccessToken_Save_Validation rejects nil pointers and empty
// IDs at the boundary so callers get a typed error rather than a
// silently-corrupted store.
func TestOpaqueAccessToken_Save_Validation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	if err := s.OpaqueAccessTokens().Save(ctx, nil); err == nil {
		t.Fatal("Save(nil) returned nil, want error")
	}
	if err := s.OpaqueAccessTokens().Save(ctx, &store.OpaqueAccessToken{}); err == nil {
		t.Fatal("Save(empty) returned nil, want error")
	}
}

// TestOpaqueAccessToken_RevokeByID exercises the per-token revocation
// path. The call is idempotent: a missing id returns nil so the
// revocation endpoint can mirror RFC 7009 §2.2 ("invalid tokens do not
// cause an error response") without an extra absence check, and a
// second call against the same id is a no-op.
func TestOpaqueAccessToken_RevokeByID(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	tok := &store.OpaqueAccessToken{
		ID:        "rev-1",
		ClientID:  "c",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.OpaqueAccessTokens().Save(ctx, tok); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := s.OpaqueAccessTokens().RevokeByID(ctx, "rev-1"); err != nil {
		t.Fatalf("RevokeByID: %v", err)
	}
	got, err := s.OpaqueAccessTokens().Find(ctx, "rev-1")
	if err != nil || got == nil {
		t.Fatalf("Find post-revoke: rec=%+v err=%v", got, err)
	}
	if !got.Revoked {
		t.Errorf("Revoked = false, want true")
	}
	// Idempotent: missing id is not an error.
	if err := s.OpaqueAccessTokens().RevokeByID(ctx, "no-such-id"); err != nil {
		t.Errorf("RevokeByID(absent) err = %v, want nil", err)
	}
	// Idempotent: second call against the same id is a no-op.
	if err := s.OpaqueAccessTokens().RevokeByID(ctx, "rev-1"); err != nil {
		t.Errorf("RevokeByID(second) err = %v, want nil", err)
	}
	// Empty id is a no-op.
	if err := s.OpaqueAccessTokens().RevokeByID(ctx, ""); err != nil {
		t.Errorf("RevokeByID(\"\") err = %v, want nil", err)
	}
}

// TestOpaqueAccessToken_RevokeByGrant cascades across every record
// sharing a GrantID, mirroring the code-replay path: a single replayed
// authorization code revokes every opaque AT issued under the same
// grant. The return value reports the number of newly-revoked rows so
// the token endpoint can log the cascade size.
func TestOpaqueAccessToken_RevokeByGrant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	exp := time.Now().Add(time.Hour)
	for _, id := range []string{"a1", "a2", "a3"} {
		if err := s.OpaqueAccessTokens().Save(ctx, &store.OpaqueAccessToken{
			ID: id, GrantID: "grant-shared", ClientID: "c", ExpiresAt: exp,
		}); err != nil {
			t.Fatalf("Save %s: %v", id, err)
		}
	}
	if err := s.OpaqueAccessTokens().Save(ctx, &store.OpaqueAccessToken{
		ID: "outside", GrantID: "grant-other", ClientID: "c", ExpiresAt: exp,
	}); err != nil {
		t.Fatalf("Save outside: %v", err)
	}
	n, err := s.OpaqueAccessTokens().RevokeByGrant(ctx, "grant-shared")
	if err != nil {
		t.Fatalf("RevokeByGrant: %v", err)
	}
	if n != 3 {
		t.Errorf("count = %d, want 3", n)
	}
	for _, id := range []string{"a1", "a2", "a3"} {
		rec, _ := s.OpaqueAccessTokens().Find(ctx, id)
		if rec == nil || !rec.Revoked {
			t.Errorf("%s: not revoked: %+v", id, rec)
		}
	}
	other, _ := s.OpaqueAccessTokens().Find(ctx, "outside")
	if other == nil || other.Revoked {
		t.Errorf("outside grant should NOT be revoked: %+v", other)
	}
	// Re-running the cascade returns 0 (idempotent: already-revoked rows
	// are not double-counted).
	n, err = s.OpaqueAccessTokens().RevokeByGrant(ctx, "grant-shared")
	if err != nil || n != 0 {
		t.Errorf("second RevokeByGrant = (%d, %v), want (0, nil)", n, err)
	}
	// Empty grantID is a no-op rather than a wildcard.
	n, _ = s.OpaqueAccessTokens().RevokeByGrant(ctx, "")
	if n != 0 {
		t.Errorf("RevokeByGrant(\"\") = %d, want 0", n)
	}
}

// TestOpaqueAccessToken_GC drops rows whose ExpiresAt is strictly
// before the supplied cutoff. Records without an ExpiresAt (zero time)
// opt out of GC so the store never silently drops a row that was
// registered without a TTL.
func TestOpaqueAccessToken_GC(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	live := &store.OpaqueAccessToken{ID: "live", ClientID: "c", ExpiresAt: now.Add(time.Hour)}
	expired := &store.OpaqueAccessToken{ID: "expired", ClientID: "c", ExpiresAt: now.Add(-time.Hour)}
	noExp := &store.OpaqueAccessToken{ID: "no-exp", ClientID: "c"}
	for _, r := range []*store.OpaqueAccessToken{live, expired, noExp} {
		if err := s.OpaqueAccessTokens().Save(ctx, r); err != nil {
			t.Fatalf("Save %s: %v", r.ID, err)
		}
	}
	n, err := s.OpaqueAccessTokens().GC(ctx, now)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if n != 1 {
		t.Errorf("GC count = %d, want 1", n)
	}
	if rec, _ := s.OpaqueAccessTokens().Find(ctx, "expired"); rec != nil {
		t.Errorf("expired record not collected: %+v", rec)
	}
	if rec, _ := s.OpaqueAccessTokens().Find(ctx, "live"); rec == nil {
		t.Error("live record removed by GC")
	}
	if rec, _ := s.OpaqueAccessTokens().Find(ctx, "no-exp"); rec == nil {
		t.Error("zero-expiry record removed by GC")
	}
}

// TestOpaqueAccessToken_HashOnStore verifies that Save hashes the raw
// id before it lands in the in-memory map: a Find against a digest of
// the raw value succeeds via the hashed lookup, but presenting the
// digest itself as the lookup key (as a poorly-implemented backend
// would do) misses because it is double-hashed. The test also asserts
// the raw ID never appears anywhere in the store's keyspace, which is
// the property a heap dump would expose.
func TestOpaqueAccessToken_HashOnStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	rawID := "raw-secret-bearer-id"
	tok := &store.OpaqueAccessToken{
		ID:        rawID,
		ClientID:  "c",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := s.OpaqueAccessTokens().Save(ctx, tok); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Find with the raw id succeeds.
	got, err := s.OpaqueAccessTokens().Find(ctx, rawID)
	if err != nil {
		t.Fatalf("Find(rawID): %v", err)
	}
	if got == nil || got.ID != rawID {
		t.Fatalf("Find(rawID) = %+v, want non-nil with raw id restored", got)
	}
	// Find with the SHA-256 hex digest (i.e. the in-process map key)
	// MUST miss: the store double-hashes the input so a leak of the
	// hashed key cannot be redeemed against the same store.
	digest := sha256.Sum256([]byte(rawID))
	if _, err := s.OpaqueAccessTokens().Find(ctx, hex.EncodeToString(digest[:])); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Find(digest) err = %v, want ErrNotFound (digest must not redeem)", err)
	}
}
