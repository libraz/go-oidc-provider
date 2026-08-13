//go:build testcontainers

package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	mysqlmod "github.com/testcontainers/testcontainers-go/modules/mysql"

	"github.com/libraz/go-oidc-provider/op/store"
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
	return newMySQLFactoryWithClientFoundRows(t, false)
}

// newMySQLFactoryWithClientFoundRows is kept separate from the normal
// contract factory so the affected-row compatibility mode is exercised by an
// explicit regression without changing the default container configuration.
func newMySQLFactoryWithClientFoundRows(t *testing.T, clientFoundRows bool) contract.Factory {
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
	clock := &fixedClock{now: contract.Reference}

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
		sub.ClientFoundRows = clientFoundRows
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
		return contract.Backend{Store: s, Now: clock.Now, SeedUser: seedContractUser(s)}
	}
}

// TestMySQL_Contract runs the full store contract harness against a
// MySQL 8.0 instance booted via testcontainers-go. The test is gated
// by the `testcontainers` build tag so a default `go test` invocation
// stays driver- and Docker-free; CI opts in via
// `go test -tags=testcontainers ./...` when Docker is available.
func TestMySQL_Contract(t *testing.T) {
	t.Parallel()
	factory := newMySQLFactory(t)
	contract.Run(t, factory)
	runMFAContracts(t, factory)
	runClientUpdateContracts(t, factory)
}

// TestMySQL_ClientFoundRowsMFAPut exercises the driver mode used by services
// that want UPDATE matched-row counts. Put must not infer a row-version
// overflow from RowsAffected: it installs a fresh opaque token in the INSERT
// row itself, so repeating an otherwise identical record remains a successful
// replacement even when clientFoundRows=true.
func TestMySQL_ClientFoundRowsMFAPut(t *testing.T) {
	factory := newMySQLFactoryWithClientFoundRows(t, true)
	b := factory(t)
	s, ok := b.Store.(*oidcsql.Store)
	if !ok {
		t.Fatalf("factory produced %T, want *oidcsql.Store", b.Store)
	}
	ctx := context.Background()

	totp := &store.TOTPRecord{
		Subject:          "client-found-rows-totp",
		SecretCiphertext: []byte{0x01, 0x02},
		ConfirmedAt:      contract.Reference,
	}
	if err := s.TOTPs().Put(ctx, totp); err != nil {
		t.Fatalf("first TOTP Put: %v", err)
	}
	totpFirst, err := s.TOTPs().Get(ctx, totp.Subject)
	if err != nil {
		t.Fatalf("first TOTP Get: %v", err)
	}
	if err := s.TOTPs().Put(ctx, totpFirst); err != nil {
		t.Fatalf("same-value TOTP Put with clientFoundRows=true: %v", err)
	}
	totpSecond, err := s.TOTPs().Get(ctx, totp.Subject)
	if err != nil {
		t.Fatalf("second TOTP Get: %v", err)
	}
	if totpSecond.Version == 0 || totpSecond.Version == totpFirst.Version {
		t.Fatalf("TOTP repeated Put Version = %d, want a fresh token after %d", totpSecond.Version, totpFirst.Version)
	}

	email := &store.EmailOTPRecord{
		Subject:     "client-found-rows-email",
		CodeSalt:    []byte{0x03},
		CodeHash:    []byte{0x04},
		SentAt:      contract.Reference,
		ExpiresAt:   contract.Reference.Add(time.Hour),
		RetainUntil: contract.Reference.Add(24 * time.Hour),
	}
	if err := s.EmailOTPs().Put(ctx, email); err != nil {
		t.Fatalf("first email OTP Put: %v", err)
	}
	emailFirst, err := s.EmailOTPs().Get(ctx, email.Subject)
	if err != nil {
		t.Fatalf("first email OTP Get: %v", err)
	}
	if err := s.EmailOTPs().Put(ctx, emailFirst); err != nil {
		t.Fatalf("same-value email OTP Put with clientFoundRows=true: %v", err)
	}
	emailSecond, err := s.EmailOTPs().Get(ctx, email.Subject)
	if err != nil {
		t.Fatalf("second email OTP Get: %v", err)
	}
	if emailSecond.Version == 0 || emailSecond.Version == emailFirst.Version {
		t.Fatalf("email OTP repeated Put Version = %d, want a fresh token after %d", emailSecond.Version, emailFirst.Version)
	}
}
