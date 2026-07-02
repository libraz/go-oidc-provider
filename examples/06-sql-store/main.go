//go:build example

// Example 06-sql-store shows how to plug the SQL storage adapter
// (op/storeadapter/sql) into a Provider. The example uses
// modernc.org/sqlite so it runs on any platform without CGO; the same
// wiring applies to MySQL (github.com/go-sql-driver/mysql) and
// PostgreSQL (github.com/jackc/pgx/v5/stdlib) by swapping the driver
// import and the [oidcsql.Dialect] argument to oidcsql.New.
//
// Run with:
//
//	(cd examples/06-sql-store && go run -tags example .)
//
// The example creates a fresh database file under the OS temp
// directory, applies the embedded v1 schema, and serves the OP on
// :8080 with one statically-provisioned client. A production embedder
// runs the schema through their own migration tooling and persists
// the database where it belongs.
//
// Manual verification:
//
//  1. Start the example and note the "sqlite store at ..." log line.
//  2. Open http://127.0.0.1:8080/.well-known/openid-configuration
//     to confirm the OP is serving from the SQL-backed store.
//  3. Inspect the logged SQLite path if you want to see the v1
//     schema tables the adapter created for the demo database.
//
// PRODUCTION CAVEATS:
//   - Keys: key derivation uses a hardcoded ephemeral value for the demo; production must derive the signing key from a vault / KMS.
//   - Store: the sqlite DSN here uses a local file; production uses Postgres / MySQL via op/storeadapter/sql, runs schema migrations through the embedder's tooling, and persists the database where it belongs.
//   - DSN: the DSN string contains credentials; production should source it from a secret manager (Vault / AWS Secrets Manager / GCP Secret Manager) rather than hard-coding it next to the binary.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
package main

import (
	"context"
	databasesql "database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	keys := devkeys.MustEphemeral("sql-store-1")

	dbPath := filepath.Join(os.TempDir(), "oidc-example-06.db")
	// Pre-v1 schemas can evolve between checkouts; remove any prior file
	// so a re-run under the new layout never collides with a stale DDL.
	// Production embedders track schema versions through their own
	// migration tooling instead of throwing the database away.
	_ = os.Remove(dbPath)
	dsn := "file:" + dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := databasesql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer func() { _ = db.Close() }()

	storage, err := oidcsql.New(db, oidcsql.SQLite())
	if err != nil {
		return fmt.Errorf("oidcsql.New: %w", err)
	}
	if err := storage.Migrate(context.Background()); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	log.Printf("sqlite store at %s", dbPath)

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(storage),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithStaticClients(op.PublicClient{
			ID:           "demo-spa",
			RedirectURIs: []string{"https://rp.example.com/cb"},
			Scopes:       []string{"openid", "profile", "email"},
		}),
	)
	if err != nil {
		return fmt.Errorf("op.New: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("OP backed by SQLite listening on :8080 (issuer https://op.example.com)")
	if err := serve.Listen(":8080", mux); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	return nil
}
