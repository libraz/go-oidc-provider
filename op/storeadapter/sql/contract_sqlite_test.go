package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// fixedClock pins the adapter to contract.Reference so the harness's
// expiry pre-conditions land at the same instant the records were
// stamped with.
type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

// openSQLite returns a fresh in-process SQLite database. Each call
// produces an isolated database via the file::memory:?cache=shared
// trick scoped to a unique URI fragment so concurrent tests can run
// in parallel without colliding on the shared memory namespace.
func openSQLite(t *testing.T) *databasesql.DB {
	t.Helper()
	// Per-test database file under the testing.T's TempDir so the
	// driver's WAL files land in a directory the test framework
	// cleans up automatically.
	dir := t.TempDir()
	dsn := "file:" + dir + "/oidc.db?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := databasesql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newSQLiteFactory returns a contract.Factory that builds a fresh,
// migrated SQLite-backed store per sub-test.
func newSQLiteFactory(t *testing.T) contract.Factory {
	t.Helper()
	clock := fixedClock{now: contract.Reference}
	return func(t *testing.T) contract.Backend {
		t.Helper()
		db := openSQLite(t)
		s, err := oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithClock(clock))
		if err != nil {
			t.Fatalf("oidcsql.New: %v", err)
		}
		if err := s.Migrate(context.Background()); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		return contract.Backend{Store: s, Now: clock.Now}
	}
}

// TestSQLite_Contract drives every contract sub-test against the
// SQLite adapter. A failure here is the first signal that an
// adapter change has broken the documented store semantics.
func TestSQLite_Contract(t *testing.T) {
	t.Parallel()
	contract.Run(t, newSQLiteFactory(t))
}

// TestSQLite_SessionStore_ConcurrentRotate pins the rotation
// post-condition declared on [store.SessionStore] directly against the
// SQL adapter. The free-standing helper is also exercised via
// [contract.Run] -> sessionCases; the explicit call documents the
// contract a sessions-only embedder is expected to honour.
func TestSQLite_SessionStore_ConcurrentRotate(t *testing.T) {
	t.Parallel()
	b := newSQLiteFactory(t)(t)
	contract.AssertConcurrentRotate(t, b.Store.Sessions(), b.Now())
}

// TestSQLite_SessionStore_ExpiredReturnsNotFound pins the
// expired-session contract against the SQL adapter via the shared
// [contract.AssertExpiredSessionReturnsNotFound] helper. The strict-
// less-than expiry boundary is checked at one source site
// (op/storeadapter/patterns.IsExpiredStrict) and observed identically
// across every backend.
func TestSQLite_SessionStore_ExpiredReturnsNotFound(t *testing.T) {
	t.Parallel()
	b := newSQLiteFactory(t)(t)
	contract.AssertExpiredSessionReturnsNotFound(t, b.Store.Sessions(), b.Now())
}

// TestSQLite_SessionStore_NotFoundOnMissing pins the absent-ID
// contract against the SQL adapter via the shared
// [contract.AssertSessionNotFoundOnMissing] helper.
func TestSQLite_SessionStore_NotFoundOnMissing(t *testing.T) {
	t.Parallel()
	b := newSQLiteFactory(t)(t)
	contract.AssertSessionNotFoundOnMissing(t, b.Store.Sessions(), b.Now())
}

// TestSQLite_SessionStore_BatchListMatches pins the chooser-group
// batch lookup contract against the SQL adapter via the shared
// [contract.AssertSessionBatchListMatches] helper.
func TestSQLite_SessionStore_BatchListMatches(t *testing.T) {
	t.Parallel()
	b := newSQLiteFactory(t)(t)
	contract.AssertSessionBatchListMatches(t, b.Store.Sessions(), 16, b.Now())
}
