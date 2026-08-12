package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// A refresh-token row outlives its own expiry. Replay revocation
// (RFC 9700 §2.2.2) resolves a chain root before it cascades, and the
// root is the oldest token in the chain and therefore the first to
// expire — so a sweep that reclaimed rows on their own expiry would
// delete the root of every chain a client is still actively refreshing,
// and every later replay on that chain would fail to resolve. The tests
// here pin the condition that prevents it.

// refreshGCFixture is a store with the refresh table seeded by the test.
type refreshGCFixture struct {
	store  *oidcsql.Store
	db     *databasesql.DB
	cutoff time.Time
}

func newRefreshGCFixture(t *testing.T) refreshGCFixture {
	t.Helper()
	ctx := context.Background()
	cutoff := contract.Reference
	db := openSQLite(t)
	s, err := oidcsql.New(db, oidcsql.SQLite(),
		oidcsql.WithClock(&fixedClock{now: cutoff.Add(10 * time.Minute)}))
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return refreshGCFixture{store: s, db: db, cutoff: cutoff}
}

// save persists one rotation record. parent is the id of the token this
// one replaces, or "" for a chain root.
func (f refreshGCFixture) save(t *testing.T, id, grantID, parent string, expiresAt time.Time) {
	t.Helper()
	var parentID *string
	if parent != "" {
		parentID = &parent
	}
	err := f.store.RefreshTokens().Save(context.Background(), &store.RefreshToken{
		ID:        id,
		ClientID:  "client-1",
		GrantID:   grantID,
		Subject:   "subject-1",
		ParentID:  parentID,
		Scope:     []string{"openid"},
		ExpiresAt: expiresAt,
		CreatedAt: f.cutoff.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("Save refresh token %s: %v", id, err)
	}
}

func (f refreshGCFixture) refreshCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := f.db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM oidc_refresh_tokens").Scan(&n); err != nil {
		t.Fatalf("count refresh tokens: %v", err)
	}
	return n
}

// TestSQLite_GC_KeepsExpiredAncestorsOfALiveChain is the security
// property. A client that has refreshed three times leaves two expired
// records behind and holds one live token; reclaiming the two would
// sever the chain from its root while the client can still present the
// third.
func TestSQLite_GC_KeepsExpiredAncestorsOfALiveChain(t *testing.T) {
	t.Parallel()

	f := newRefreshGCFixture(t)
	f.save(t, "rt-root", "grant-live", "", f.cutoff.Add(-2*time.Hour))
	f.save(t, "rt-mid", "grant-live", "rt-root", f.cutoff.Add(-time.Hour))
	f.save(t, "rt-tip", "grant-live", "rt-mid", f.cutoff.Add(time.Hour))

	stats, err := f.store.GC(context.Background(), f.cutoff)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if stats.RefreshTokens != 0 {
		t.Errorf("GC deleted %d refresh rows from a chain whose tip is live, want 0", stats.RefreshTokens)
	}
	if got := f.refreshCount(t); got != 3 {
		t.Errorf("refresh rows = %d, want all 3 retained", got)
	}
}

// TestSQLite_GC_ReclaimsAWhollyExpiredChain is the counterpart: once no
// token on the grant can be redeemed, nothing downstream can ask about
// the chain and the rows are dead weight.
func TestSQLite_GC_ReclaimsAWhollyExpiredChain(t *testing.T) {
	t.Parallel()

	f := newRefreshGCFixture(t)
	f.save(t, "rt-root", "grant-dead", "", f.cutoff.Add(-2*time.Hour))
	f.save(t, "rt-mid", "grant-dead", "rt-root", f.cutoff.Add(-time.Hour))
	f.save(t, "rt-tip", "grant-dead", "rt-mid", f.cutoff.Add(-time.Minute))

	stats, err := f.store.GC(context.Background(), f.cutoff)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if stats.RefreshTokens != 3 {
		t.Errorf("GC deleted %d refresh rows, want the whole dead chain (3)", stats.RefreshTokens)
	}
	if got := f.refreshCount(t); got != 0 {
		t.Errorf("refresh rows = %d, want 0", got)
	}
}

// TestSQLite_GC_KeepsADeadChainWhileASiblingChainLives pins the coarse
// grouping. Liveness is decided per grant because the table records no
// chain root, so a dead chain is retained while another chain on the
// same grant is still in use. That over-retains, which is the direction
// the rule is allowed to be wrong in.
func TestSQLite_GC_KeepsADeadChainWhileASiblingChainLives(t *testing.T) {
	t.Parallel()

	f := newRefreshGCFixture(t)
	f.save(t, "rt-old-root", "grant-shared", "", f.cutoff.Add(-2*time.Hour))
	f.save(t, "rt-old-tip", "grant-shared", "rt-old-root", f.cutoff.Add(-time.Hour))
	f.save(t, "rt-new-root", "grant-shared", "", f.cutoff.Add(time.Hour))

	stats, err := f.store.GC(context.Background(), f.cutoff)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if stats.RefreshTokens != 0 {
		t.Errorf("GC deleted %d rows from a grant that still has a live token, want 0", stats.RefreshTokens)
	}
	if got := f.refreshCount(t); got != 3 {
		t.Errorf("refresh rows = %d, want all 3 retained", got)
	}
}

// TestSQLite_GC_ReclaimsOneGrantWithoutTouchingAnother keeps the
// grouping from collapsing into "all or nothing": a dead grant is
// reclaimed even while an unrelated grant is live.
func TestSQLite_GC_ReclaimsOneGrantWithoutTouchingAnother(t *testing.T) {
	t.Parallel()

	f := newRefreshGCFixture(t)
	f.save(t, "rt-dead", "grant-dead", "", f.cutoff.Add(-time.Hour))
	f.save(t, "rt-live", "grant-live", "", f.cutoff.Add(time.Hour))

	stats, err := f.store.GC(context.Background(), f.cutoff)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if stats.RefreshTokens != 1 {
		t.Errorf("GC deleted %d rows, want only the dead grant's single row", stats.RefreshTokens)
	}
	if _, err := f.store.RefreshTokens().Find(context.Background(), "rt-live"); err != nil {
		t.Errorf("Find live token after sweep: %v", err)
	}
}

// TestSQLite_GC_KeepsRefreshRowsWithoutExpiry matches the rule the other
// swept tables follow: a zero expires_at means "no expiry", never "long
// expired". Here it also pins the grant's whole history, since a token
// that never expires can be presented at any time.
func TestSQLite_GC_KeepsRefreshRowsWithoutExpiry(t *testing.T) {
	t.Parallel()

	f := newRefreshGCFixture(t)
	f.save(t, "rt-root", "grant-eternal", "", f.cutoff.Add(-time.Hour))
	f.save(t, "rt-tip", "grant-eternal", "rt-root", time.Time{})

	stats, err := f.store.GC(context.Background(), f.cutoff)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if stats.RefreshTokens != 0 {
		t.Errorf("GC deleted %d rows from a grant holding a token without expiry, want 0", stats.RefreshTokens)
	}
	if got := f.refreshCount(t); got != 2 {
		t.Errorf("refresh rows = %d, want both retained", got)
	}
}

// TestSQLite_GC_LeavesASurvivingChainRevocable is the end of the
// argument the retention rule exists for: after a sweep that reclaimed
// an unrelated dead grant, a replay cascade on the surviving chain must
// still resolve from its root and retire every descendant.
func TestSQLite_GC_LeavesASurvivingChainRevocable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newRefreshGCFixture(t)
	f.save(t, "rt-dead", "grant-dead", "", f.cutoff.Add(-time.Hour))
	f.save(t, "rt-root", "grant-live", "", f.cutoff.Add(-2*time.Hour))
	f.save(t, "rt-tip", "grant-live", "rt-root", f.cutoff.Add(time.Hour))

	if _, err := f.store.GC(ctx, f.cutoff); err != nil {
		t.Fatalf("GC: %v", err)
	}
	if err := f.store.RefreshTokens().RevokeChain(ctx, "rt-root"); err != nil {
		t.Fatalf("RevokeChain from a root the sweep had to retain: %v", err)
	}
	tip, err := f.store.RefreshTokens().Find(ctx, "rt-tip")
	if err != nil {
		t.Fatalf("Find tip after cascade: %v", err)
	}
	if !tip.Revoked {
		t.Error("the cascade did not reach the live descendant; the chain graph did not survive the sweep")
	}
}

// TestSQLite_GC_RefreshSweepIsRepeatable keeps the sweep safe to retry
// after a partial failure: the second run finds nothing left to do
// rather than reporting the same work twice.
func TestSQLite_GC_RefreshSweepIsRepeatable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newRefreshGCFixture(t)
	f.save(t, "rt-dead", "grant-dead", "", f.cutoff.Add(-time.Hour))

	first, err := f.store.GC(ctx, f.cutoff)
	if err != nil {
		t.Fatalf("first GC: %v", err)
	}
	second, err := f.store.GC(ctx, f.cutoff)
	if err != nil {
		t.Fatalf("second GC: %v", err)
	}
	if first.RefreshTokens != 1 || second.RefreshTokens != 0 {
		t.Errorf("refresh sweep counts = (%d, %d), want (1, 0)", first.RefreshTokens, second.RefreshTokens)
	}
}
