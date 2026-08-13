package oidcsql_test

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// The retention sweep is the one statement group an embedder runs on a
// schedule rather than on a request, so a dialect that rejects it — or
// quietly answers it differently — fails in production long after the
// deployment that introduced it. runGCAcrossEngine is shared by the SQLite
// case here and the MySQL / PostgreSQL cases in gc_engines_test.go, which
// build only under the testcontainers tag; running the identical fixture on
// all three is what makes a divergence visible as a divergence.

func TestSQLite_GC(t *testing.T) {
	t.Parallel()
	runGCAcrossEngine(t, newSQLiteFactory(t))
}

func runGCAcrossEngine(t *testing.T, f contract.Factory) {
	t.Helper()
	b := f(t)
	s, ok := b.Store.(*oidcsql.Store)
	if !ok {
		t.Fatalf("factory produced %T, want *oidcsql.Store", b.Store)
	}
	ctx := t.Context()
	cutoff := b.Now()

	if err := s.Sessions().Save(ctx, &store.Session{
		ID: "session-dead", Subject: "subject-1",
		ExpiresAt: cutoff.Add(-time.Hour),
		CreatedAt: cutoff.Add(-2 * time.Hour),
		UpdatedAt: cutoff.Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("Save expired session: %v", err)
	}
	if err := s.Sessions().Save(ctx, &store.Session{
		ID: "session-live", Subject: "subject-1",
		ExpiresAt: cutoff.Add(time.Hour),
		CreatedAt: cutoff, UpdatedAt: cutoff,
	}); err != nil {
		t.Fatalf("Save live session: %v", err)
	}
	if err := s.Interactions().Save(ctx, &store.Interaction{
		ID: "interaction-dead", ClientID: "client-1", Step: "login",
		RawState: []byte("{}"), ExpiresAt: cutoff.Add(-time.Hour),
		CreatedAt: cutoff.Add(-2 * time.Hour), UpdatedAt: cutoff.Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("Save expired interaction: %v", err)
	}
	if err := s.PushedAuthRequests().Save(ctx, &store.PushedAuthRequest{
		URI: "urn:ietf:params:oauth:request_uri:dead", ClientID: "client-1",
		RawParams: []byte("response_type=code"),
		ExpiresAt: cutoff.Add(-time.Hour), CreatedAt: cutoff.Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("Save expired PAR: %v", err)
	}
	seedRefreshChains(t, s, cutoff)

	stats, err := s.GC(ctx, cutoff)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if stats.Sessions != 1 || stats.Interactions != 1 || stats.PushedAuthRequests != 1 {
		t.Errorf("GC reported %+v, want one row per seeded expired table", stats)
	}
	if stats.RefreshTokens != 2 {
		t.Errorf("GC reported RefreshTokens=%d, want the dead grant's 2 rows and neither of the live grant's",
			stats.RefreshTokens)
	}
	if _, err := s.Sessions().Find(ctx, "session-live"); err != nil {
		t.Errorf("Find live session after the sweep: %v", err)
	}
	assertDeadChainIsGone(t, s, cutoff)
	assertRefreshRetention(t, s)
}

// seedRefreshChains plants the two-grant fixture the retention rule is
// written against: one grant whose every rotation record has expired, and one
// whose root has expired while its tip is still redeemable.
//
// The refresh sweep is the statement in the group most exposed to dialect
// difference. It is a self-referencing anti-join — delete rows of grants that
// have no live row — and MySQL rejects reading the target table of a DELETE
// in its own subquery (ER_UPDATE_TABLE_USED), so the query wraps the subquery
// in a derived table to get around it. That wrapping is the part no other
// statement in the sweep needs, and until both sides of its predicate have
// rows on a real engine, nothing exercises it.
func seedRefreshChains(t *testing.T, s *oidcsql.Store, cutoff time.Time) {
	t.Helper()

	ctx := t.Context()
	save := func(id, grantID, parent string, expiresAt time.Time) {
		t.Helper()
		var parentID *string
		if parent != "" {
			parentID = &parent
		}
		if err := s.RefreshTokens().Save(ctx, &store.RefreshToken{
			ID: id, ClientID: "client-1", GrantID: grantID, Subject: "subject-1",
			ParentID: parentID, Scope: []string{"openid"},
			ExpiresAt: expiresAt, CreatedAt: cutoff.Add(-2 * time.Hour),
		}); err != nil {
			t.Fatalf("Save refresh token %s: %v", id, err)
		}
	}

	save("rt-dead-root", "grant-dead", "", cutoff.Add(-2*time.Hour))
	save("rt-dead-tip", "grant-dead", "rt-dead-root", cutoff.Add(-time.Hour))

	save("rt-live-root", "grant-live", "", cutoff.Add(-2*time.Hour))
	save("rt-live-tip", "grant-live", "rt-live-root", cutoff.Add(time.Hour))
}

// assertRefreshRetention checks the side of the predicate a deletion count
// cannot see. Counting alone would pass on a sweep that removed two arbitrary
// rows, and the expired ancestor of a live chain is the row whose loss is
// silent: the chain keeps working until a replay arrives and cannot be
// resolved back to its root.
//
// The check runs a replay cascade rather than looking the row up, because
// Find applies the expiry bound — an expired ancestor is correctly not
// findable whether or not the sweep kept it, so Find cannot distinguish
// retained from reclaimed here. RevokeChain resolves by identifier and is
// exactly what replay revocation does, so a cascade that starts at the
// expired root and reaches the live tip proves both that the row survived
// and that it is still good for the one thing it was retained for.
func assertRefreshRetention(t *testing.T, s *oidcsql.Store) {
	t.Helper()

	ctx := t.Context()
	if err := s.RefreshTokens().RevokeChain(ctx, "rt-live-root"); err != nil {
		t.Fatalf("RevokeChain from the expired root of a live chain: %v; the sweep reclaimed an "+
			"ancestor replay revocation still has to resolve", err)
	}
	tip, err := s.RefreshTokens().Find(ctx, "rt-live-tip")
	if err != nil {
		t.Fatalf("Find the live tip after the cascade: %v", err)
	}
	if !tip.Revoked {
		t.Error("the cascade did not reach the live descendant; the chain graph did not survive the sweep")
	}
}

// assertDeadChainIsGone confirms the reclaimed rows actually left the table. A
// second sweep over the same cutoff has nothing to find, which a sweep that
// had merely mis-counted the first time would contradict.
func assertDeadChainIsGone(t *testing.T, s *oidcsql.Store, cutoff time.Time) {
	t.Helper()

	stats, err := s.GC(t.Context(), cutoff)
	if err != nil {
		t.Fatalf("second GC: %v", err)
	}
	if stats.RefreshTokens != 0 {
		t.Errorf("a repeat sweep reclaimed %d further refresh rows, want 0; the first sweep left the "+
			"dead grant behind or reported work it did not do", stats.RefreshTokens)
	}
}
