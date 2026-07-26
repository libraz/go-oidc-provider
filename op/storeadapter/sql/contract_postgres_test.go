//go:build testcontainers

package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"fmt"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	postgresmod "github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// postgresImage pins the engine version the contract harness validates
// against. 16-alpine is the smallest current major; bumping it must
// coincide with re-running the full contract suite.
const postgresImage = "postgres:16-alpine"

// newPostgresFactory boots a single PostgreSQL container, opens an
// admin connection, and returns a [contract.Factory] that creates a
// fresh database per sub-test. The container terminates via
// [testing.T.Cleanup] after the parent test (and all parallel
// sub-tests) finishes. If Docker is not reachable the parent test is
// skipped rather than failed. RELEASE_CONTRACT_REQUIRED=1 upgrades that
// absence to a failure for release gates.
func newPostgresFactory(t *testing.T) contract.Factory {
	t.Helper()
	ctx := context.Background()

	ctr, err := postgresmod.Run(ctx, postgresImage,
		postgresmod.WithDatabase("oidc_admin"),
		postgresmod.WithUsername("oidc"),
		postgresmod.WithPassword("oidcpw"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		if os.Getenv("RELEASE_CONTRACT_REQUIRED") == "1" {
			t.Fatalf("postgres container required for release contract: %v", err)
		}
		t.Skipf("postgres container unavailable (Docker not running?): %v", err)
	}
	t.Cleanup(func() {
		_ = ctr.Terminate(context.Background())
	})

	adminDSN, err := ctr.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("ConnectionString: %v", err)
	}

	admin, err := databasesql.Open("pgx", adminDSN)
	if err != nil {
		t.Fatalf("open admin: %v", err)
	}
	admin.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = admin.Close() })

	var seq atomic.Uint64
	clock := fixedClock{now: contract.Reference}

	return func(t *testing.T) contract.Backend {
		t.Helper()
		dbName := fmt.Sprintf("oidc_t_%d", seq.Add(1))
		// CREATE DATABASE is not transactional in postgres; database/sql
		// runs each Exec without an enclosing tx so the statement
		// executes directly against the server.
		if _, err := admin.ExecContext(t.Context(), `CREATE DATABASE "`+dbName+`"`); err != nil {
			t.Fatalf("CREATE DATABASE %s: %v", dbName, err)
		}

		dsn := rewritePostgresDB(t, adminDSN, dbName)
		db, err := databasesql.Open("pgx", dsn)
		if err != nil {
			t.Fatalf("open %s: %v", dbName, err)
		}
		t.Cleanup(func() {
			_ = db.Close()
			// WITH (FORCE) terminates lingering connections (PG 13+),
			// avoiding the race where DROP fails because the test's
			// pool has not finished closing.
			_, _ = admin.ExecContext(context.Background(),
				`DROP DATABASE IF EXISTS "`+dbName+`" WITH (FORCE)`)
		})

		s, err := oidcsql.New(db, oidcsql.Postgres(), oidcsql.WithClock(clock))
		if err != nil {
			t.Fatalf("oidcsql.New: %v", err)
		}
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		return contract.Backend{Store: s, Now: clock.Now, SeedUser: seedContractUser(s)}
	}
}

// rewritePostgresDB swaps the database path in a postgres URL DSN
// while preserving every other component (host, port, credentials,
// query parameters). The helper exists so the per-sub-test factory
// can target a fresh database without re-deriving the credentials.
func rewritePostgresDB(t *testing.T, dsn, dbName string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse postgres dsn: %v", err)
	}
	u.Path = "/" + dbName
	return u.String()
}

// TestPostgres_Contract runs the full store contract harness against a
// PostgreSQL 16 instance booted via testcontainers-go. The test is
// gated by the `testcontainers` build tag so a default `go test`
// invocation stays driver- and Docker-free; CI opts in via
// `go test -tags=testcontainers ./...` when Docker is available.
func TestPostgres_Contract(t *testing.T) {
	t.Parallel()
	factory := newPostgresFactory(t)
	contract.Run(t, factory)
	runMFAContracts(t, factory)
}
