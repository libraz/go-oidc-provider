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
