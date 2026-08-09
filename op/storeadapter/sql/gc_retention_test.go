package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// gcFixture seeds the four tables Store.GC sweeps with one row on each
// side of the cutoff. The store's clock is deliberately set ahead of
// the cutoff so the fixture also covers a row that goes stale while a
// sweep is in flight: such a row is expired against the wall clock but
// not against the cutoff the sweep was given, and the sweep must leave
// it alone rather than make a decision the caller did not ask for.
type gcFixture struct {
	store  *oidcsql.Store
	db     *databasesql.DB
	cutoff time.Time
	now    time.Time
}

func newGCFixture(t *testing.T) gcFixture {
	t.Helper()
	ctx := context.Background()
	cutoff := contract.Reference
	// The sweep is driven by the cutoff, not by the adapter's clock.
	now := cutoff.Add(10 * time.Minute)

	db := openSQLite(t)
	s, err := oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithClock(&fixedClock{now: now}))
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	// dead expired before the cutoff, boundary expires exactly at it,
	// straggler expires inside the sweep window, and live outlives all
	// three.
	stamps := map[string]time.Time{
		"dead":      cutoff.Add(-time.Second),
		"boundary":  cutoff,
		"straggler": cutoff.Add(time.Minute),
		"live":      now.Add(time.Hour),
	}
	for name, expiresAt := range stamps {
		if err := s.AuthorizationCodes().Save(ctx, &store.AuthorizationCode{
			ID: "code-" + name, ClientID: "client-1", GrantID: "grant-1",
			Subject: "subject-1", RedirectURI: "https://rp.example/cb",
			Scope: []string{"openid"}, ExpiresAt: expiresAt, CreatedAt: cutoff.Add(-time.Hour),
		}); err != nil {
			t.Fatalf("Save authorization code %s: %v", name, err)
		}
		if err := s.PushedAuthRequests().Save(ctx, &store.PushedAuthRequest{
			URI: "urn:ietf:params:oauth:request_uri:" + name, ClientID: "client-1",
			RawParams: []byte("response_type=code"),
			ExpiresAt: expiresAt, CreatedAt: cutoff.Add(-time.Hour),
		}); err != nil {
			t.Fatalf("Save PAR %s: %v", name, err)
		}
		if err := s.Interactions().Save(ctx, &store.Interaction{
			ID: "interaction-" + name, ClientID: "client-1", Step: "login",
			RawState: []byte("{}"), ExpiresAt: expiresAt,
			CreatedAt: cutoff.Add(-time.Hour), UpdatedAt: cutoff.Add(-time.Hour),
		}); err != nil {
			t.Fatalf("Save interaction %s: %v", name, err)
		}
		if err := s.Sessions().Save(ctx, &store.Session{
			ID: "session-" + name, Subject: "subject-1", ExpiresAt: expiresAt,
			CreatedAt: cutoff.Add(-time.Hour), UpdatedAt: cutoff.Add(-time.Hour),
		}); err != nil {
			t.Fatalf("Save session %s: %v", name, err)
		}
	}
	return gcFixture{store: s, db: db, cutoff: cutoff, now: now}
}

func (f gcFixture) count(t *testing.T, table string) int {
	t.Helper()
	var n int
	if err := f.db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM "+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestSQLite_GC_DeletesOnlyRowsExpiredBeforeCutoff(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newGCFixture(t)

	tables := []string{
		"oidc_authorization_codes",
		"oidc_par_records",
		"oidc_interactions",
		"oidc_sessions",
	}
	for _, table := range tables {
		if got := f.count(t, table); got != 4 {
			t.Fatalf("%s holds %d rows before the sweep, want 4", table, got)
		}
	}

	stats, err := f.store.GC(ctx, f.cutoff)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	want := oidcsql.GCStats{
		AuthorizationCodes: 1,
		PushedAuthRequests: 1,
		Interactions:       1,
		Sessions:           1,
	}
	if stats != want {
		t.Errorf("GC reported %+v, want %+v", stats, want)
	}
	if stats.Total() != 4 {
		t.Errorf("GCStats.Total() = %d, want 4", stats.Total())
	}

	for _, table := range tables {
		if got := f.count(t, table); got != 3 {
			t.Errorf("%s holds %d rows after the sweep, want 3 "+
				"(only the row expired strictly before the cutoff may go)", table, got)
		}
	}

	// The row that expires exactly at the cutoff and the one that
	// expires inside the sweep window are both still on disk: the sweep
	// decides on the cutoff it was given, not on the wall clock it
	// happened to observe.
	for _, name := range []string{"boundary", "straggler", "live"} {
		var n int
		if err := f.db.QueryRowContext(ctx,
			"SELECT COUNT(*) FROM oidc_sessions WHERE id = ?", "session-"+name).Scan(&n); err != nil {
			t.Fatalf("probe session-%s: %v", name, err)
		}
		if n != 1 {
			t.Errorf("session-%s was swept; only rows expired before the cutoff may be deleted", name)
		}
	}
}

func TestSQLite_GC_LeavesLiveRecordsReadable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newGCFixture(t)

	if _, err := f.store.GC(ctx, f.cutoff); err != nil {
		t.Fatalf("GC: %v", err)
	}

	if _, err := f.store.AuthorizationCodes().Find(ctx, "code-live"); err != nil {
		t.Errorf("Find live authorization code after the sweep: %v", err)
	}
	if _, err := f.store.PushedAuthRequests().Find(ctx, "urn:ietf:params:oauth:request_uri:live"); err != nil {
		t.Errorf("Find live PAR record after the sweep: %v", err)
	}
	if _, err := f.store.Interactions().Find(ctx, "interaction-live"); err != nil {
		t.Errorf("Find live interaction after the sweep: %v", err)
	}
	if _, err := f.store.Sessions().Find(ctx, "session-live"); err != nil {
		t.Errorf("Find live session after the sweep: %v", err)
	}
	// The swept row is gone from the table, and the lookup reports the
	// same absence it reported while the row was merely expired.
	if _, err := f.store.Sessions().Find(ctx, "session-dead"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("Find swept session: want ErrNotFound, got %v", err)
	}
}

func TestSQLite_GC_IsRepeatable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newGCFixture(t)

	if _, err := f.store.GC(ctx, f.cutoff); err != nil {
		t.Fatalf("first GC: %v", err)
	}
	stats, err := f.store.GC(ctx, f.cutoff)
	if err != nil {
		t.Fatalf("second GC: %v", err)
	}
	if stats.Total() != 0 {
		t.Errorf("second GC deleted %d rows, want 0 (the sweep must be safe to repeat)", stats.Total())
	}

	// Advancing the cutoff past the remaining rows reclaims them.
	stats, err = f.store.GC(ctx, f.now)
	if err != nil {
		t.Fatalf("third GC: %v", err)
	}
	if stats.Total() != 8 {
		t.Errorf("advanced GC deleted %d rows, want 8 (two per table)", stats.Total())
	}
}

func TestSQLite_GC_KeepsRowsWithoutExpiry(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newGCFixture(t)

	// A zero expires_at means "no expiry" everywhere else in the
	// adapter; the sweep has to honour the same convention or an
	// embedder who writes such a row loses it on the next cron tick.
	if _, err := f.db.ExecContext(ctx,
		"INSERT INTO oidc_sessions (id, subject, expires_at, updated_at, created_at) VALUES (?, ?, 0, 0, 0)",
		"session-no-expiry", "subject-1"); err != nil {
		t.Fatalf("insert row without expiry: %v", err)
	}

	if _, err := f.store.GC(ctx, f.now.Add(24*time.Hour)); err != nil {
		t.Fatalf("GC: %v", err)
	}

	var n int
	if err := f.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM oidc_sessions WHERE id = ?", "session-no-expiry").Scan(&n); err != nil {
		t.Fatalf("probe: %v", err)
	}
	if n != 1 {
		t.Error("the sweep deleted a row whose expires_at is zero")
	}
}

func TestSQLite_GC_HonoursNamingOverrides(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	db := openSQLite(t)
	s, err := oidcsql.New(db, oidcsql.SQLite(),
		oidcsql.WithClock(&fixedClock{now: contract.Reference}),
		oidcsql.WithNaming(map[string]string{"sessions": "tenant_sessions"}))
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := s.Sessions().Save(ctx, &store.Session{
		ID: "session-dead", Subject: "subject-1",
		ExpiresAt: contract.Reference.Add(-time.Hour),
		CreatedAt: contract.Reference.Add(-2 * time.Hour),
		UpdatedAt: contract.Reference.Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	stats, err := s.GC(ctx, contract.Reference)
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if stats.Sessions != 1 {
		t.Fatalf("GC deleted %d session rows from the renamed table, want 1", stats.Sessions)
	}
}
