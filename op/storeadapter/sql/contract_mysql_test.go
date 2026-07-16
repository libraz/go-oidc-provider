//go:build testcontainers

package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"fmt"
	"os"
	"sync/atomic"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	mysqlmod "github.com/testcontainers/testcontainers-go/modules/mysql"

	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// mysqlImage pins the engine version the contract harness validates
// against. 8.4 is the current LTS release. Bumping this must coincide
// with re-running the full contract suite, and must stay aligned with
// the example compose files (examples/07-mysql-store, examples/09-redis-volatile).
const mysqlImage = "mysql:8.4"

// newMySQLFactory boots a single MySQL container for the calling test,
// opens a root admin connection, and returns a [contract.Factory] that
// creates a fresh database per sub-test. The container terminates via
// [testing.T.Cleanup] after the parent test (and all parallel
// sub-tests) finishes. If Docker is not reachable the parent test is
// skipped rather than failed — opt-in tests must not break a default
// `go test` run. RELEASE_CONTRACT_REQUIRED=1 upgrades that absence to
// a failure for release gates.
func newMySQLFactory(t *testing.T) contract.Factory {
	t.Helper()
	ctx := context.Background()

	ctr, err := mysqlmod.Run(ctx, mysqlImage,
		mysqlmod.WithUsername("root"),
		mysqlmod.WithPassword("oidcpw"),
		mysqlmod.WithDatabase("oidc_admin"),
	)
	if err != nil {
		if os.Getenv("RELEASE_CONTRACT_REQUIRED") == "1" {
			t.Fatalf("mysql container required for release contract: %v", err)
		}
		t.Skipf("mysql container unavailable (Docker not running?): %v", err)
	}
	t.Cleanup(func() {
		_ = ctr.Terminate(context.Background())
	})

	adminDSN, err := ctr.ConnectionString(ctx, "parseTime=true", "multiStatements=true")
	if err != nil {
		t.Fatalf("ConnectionString: %v", err)
	}
	baseCfg, err := mysqldriver.ParseDSN(adminDSN)
	if err != nil {
		t.Fatalf("ParseDSN: %v", err)
	}

	admin, err := databasesql.Open("mysql", adminDSN)
	if err != nil {
		t.Fatalf("open admin: %v", err)
	}
	admin.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = admin.Close() })

	var seq atomic.Uint64
	clock := fixedClock{now: contract.Reference}

	return func(t *testing.T) contract.Backend {
		t.Helper()
		// Database name is built from a process-local counter so it
		// satisfies MySQL's regular identifier grammar without quoting
		// (purely [a-z_0-9]).
		dbName := fmt.Sprintf("oidc_t_%d", seq.Add(1))
		if _, err := admin.ExecContext(t.Context(), "CREATE DATABASE `"+dbName+"`"); err != nil {
			t.Fatalf("CREATE DATABASE %s: %v", dbName, err)
		}

		sub := *baseCfg
		sub.DBName = dbName
		db, err := databasesql.Open("mysql", sub.FormatDSN())
		if err != nil {
			t.Fatalf("open %s: %v", dbName, err)
		}
		t.Cleanup(func() {
			_ = db.Close()
			_, _ = admin.ExecContext(context.Background(), "DROP DATABASE `"+dbName+"`")
		})

		s, err := oidcsql.New(db, oidcsql.MySQL(), oidcsql.WithClock(clock))
		if err != nil {
			t.Fatalf("oidcsql.New: %v", err)
		}
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		return contract.Backend{Store: s, Now: clock.Now}
	}
}

// TestMySQL_Contract runs the full store contract harness against a
// MySQL 8.0 instance booted via testcontainers-go. The test is gated
// by the `testcontainers` build tag so a default `go test` invocation
// stays driver- and Docker-free; CI opts in via
// `go test -tags=testcontainers ./...` when Docker is available.
func TestMySQL_Contract(t *testing.T) {
	t.Parallel()
	contract.Run(t, newMySQLFactory(t))
}
