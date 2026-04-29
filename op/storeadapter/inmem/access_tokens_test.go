package inmem_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestAccessTokenRegister_RoundTrip locks in the happy path: a freshly
// registered record is reachable via Find with every field intact.
func TestAccessTokenRegister_RoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	r := store.AccessTokenRecord{
		JTI:       "jti-1",
		GrantID:   "grant-1",
		Subject:   "user-1",
		ClientID:  "client-1",
		Scopes:    []string{"openid", "profile"},
		IssuedAt:  time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 4, 29, 12, 5, 0, 0, time.UTC),
	}
	if err := s.AccessTokens().Register(ctx, r); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, err := s.AccessTokens().Find(ctx, "jti-1")
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got == nil {
		t.Fatal("Find: got nil, want record")
	}
	if got.GrantID != "grant-1" || got.Subject != "user-1" || got.ClientID != "client-1" {
		t.Errorf("identity fields: got %+v", got)
	}
	if got.Revoked {
		t.Errorf("Revoked = true on fresh record")
	}
	if len(got.Scopes) != 2 || got.Scopes[0] != "openid" || got.Scopes[1] != "profile" {
		t.Errorf("Scopes = %v", got.Scopes)
	}
}

// TestAccessTokenRegister_Duplicate confirms Register surfaces
// ErrAlreadyExists rather than silently overwriting an existing JTI.
// JTIs are crypto/rand-generated 256-bit values so the duplicate path
// is reachable only by implementation bugs; surfacing a typed error
// lets the token endpoint refuse to issue a token whose shadow row is
// in an unexpected state.
func TestAccessTokenRegister_Duplicate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	r := store.AccessTokenRecord{JTI: "dup", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.AccessTokens().Register(ctx, r); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	if err := s.AccessTokens().Register(ctx, r); err == nil {
		t.Fatal("second Register: nil error, want ErrAlreadyExists")
	}
}

// TestAccessTokenFind_AbsentReturnsNil locks in the (nil, nil) absent
// shape. A typed ErrNotFound would also be valid
// per the interface; this test pins the inmem return so callers that
// expect (nil, nil) (the userinfo / introspection paths) keep working.
func TestAccessTokenFind_AbsentReturnsNil(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	got, err := s.AccessTokens().Find(ctx, "no-such-jti")
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if got != nil {
		t.Errorf("rec = %+v, want nil", got)
	}
}

// TestAccessTokenRevokeByJTI exercises the per-token revocation path.
// The call is idempotent: a missing JTI returns nil so the revocation
// endpoint can mirror RFC 7009 §2.2 ("invalid tokens do not cause an
// error response") without an extra absence check.
func TestAccessTokenRevokeByJTI(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	r := store.AccessTokenRecord{JTI: "jti-rev", ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.AccessTokens().Register(ctx, r); err != nil {
		t.Fatalf("Register: %v", err)
	}
	if err := s.AccessTokens().RevokeByJTI(ctx, "jti-rev"); err != nil {
		t.Fatalf("RevokeByJTI: %v", err)
	}
	got, err := s.AccessTokens().Find(ctx, "jti-rev")
	if err != nil || got == nil {
		t.Fatalf("Find post-revoke: rec=%+v err=%v", got, err)
	}
	if !got.Revoked {
		t.Errorf("Revoked = false, want true")
	}
	// Idempotent: missing JTI is not an error.
	if err := s.AccessTokens().RevokeByJTI(ctx, "no-such-jti"); err != nil {
		t.Errorf("RevokeByJTI(absent) err = %v, want nil", err)
	}
	// Idempotent: second call against the same JTI is a no-op.
	if err := s.AccessTokens().RevokeByJTI(ctx, "jti-rev"); err != nil {
		t.Errorf("RevokeByJTI(second) err = %v, want nil", err)
	}
}

// TestAccessTokenRevokeByGrant cascades across every record sharing a
// GrantID, mirroring the code-replay path: a single replayed
// authorization code revokes every AT issued under the same grant.
// The return value reports the number of newly-revoked rows so the
// token endpoint can log the cascade size at slog.Info.
func TestAccessTokenRevokeByGrant(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	exp := time.Now().Add(time.Hour)
	for _, jti := range []string{"a1", "a2", "a3"} {
		if err := s.AccessTokens().Register(ctx, store.AccessTokenRecord{
			JTI: jti, GrantID: "grant-shared", ExpiresAt: exp,
		}); err != nil {
			t.Fatalf("Register %s: %v", jti, err)
		}
	}
	if err := s.AccessTokens().Register(ctx, store.AccessTokenRecord{
		JTI: "outside", GrantID: "grant-other", ExpiresAt: exp,
	}); err != nil {
		t.Fatalf("Register outside: %v", err)
	}
	n, err := s.AccessTokens().RevokeByGrant(ctx, "grant-shared")
	if err != nil {
		t.Fatalf("RevokeByGrant: %v", err)
	}
	if n != 3 {
		t.Errorf("count = %d, want 3", n)
	}
	for _, jti := range []string{"a1", "a2", "a3"} {
		rec, _ := s.AccessTokens().Find(ctx, jti)
		if rec == nil || !rec.Revoked {
			t.Errorf("%s: not revoked: %+v", jti, rec)
		}
	}
	other, _ := s.AccessTokens().Find(ctx, "outside")
	if other == nil || other.Revoked {
		t.Errorf("outside grant should NOT be revoked: %+v", other)
	}
	// Re-running the cascade returns 0 (idempotent: already-revoked
	// rows are not double-counted).
	n, err = s.AccessTokens().RevokeByGrant(ctx, "grant-shared")
	if err != nil || n != 0 {
		t.Errorf("second RevokeByGrant = (%d, %v), want (0, nil)", n, err)
	}
	// Empty grantID is a no-op rather than a wildcard.
	n, _ = s.AccessTokens().RevokeByGrant(ctx, "")
	if n != 0 {
		t.Errorf("RevokeByGrant(\"\") = %d, want 0", n)
	}
}

// TestAccessTokenGC drops rows whose ExpiresAt is strictly before the
// supplied cutoff. Records without an ExpiresAt (zero time) opt out of
// GC so the registry never silently drops a row that was registered
// without a TTL.
func TestAccessTokenGC(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := inmem.New()
	now := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	live := store.AccessTokenRecord{JTI: "live", ExpiresAt: now.Add(time.Hour)}
	expired := store.AccessTokenRecord{JTI: "expired", ExpiresAt: now.Add(-time.Hour)}
	noExp := store.AccessTokenRecord{JTI: "no-exp"}
	for _, r := range []store.AccessTokenRecord{live, expired, noExp} {
		if err := s.AccessTokens().Register(ctx, r); err != nil {
			t.Fatalf("Register %s: %v", r.JTI, err)
		}
	}
	n, err := s.AccessTokens().GC(ctx, now)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if n != 1 {
		t.Errorf("GC count = %d, want 1", n)
	}
	if rec, _ := s.AccessTokens().Find(ctx, "expired"); rec != nil {
		t.Errorf("expired record not collected: %+v", rec)
	}
	if rec, _ := s.AccessTokens().Find(ctx, "live"); rec == nil {
		t.Error("live record removed by GC")
	}
	if rec, _ := s.AccessTokens().Find(ctx, "no-exp"); rec == nil {
		t.Error("zero-expiry record removed by GC")
	}
}
