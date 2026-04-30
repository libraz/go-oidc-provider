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
//	go run -tags example ./examples/06-sql-store
//
// The example creates a fresh database file under the OS temp
// directory, applies the embedded v1 schema, and serves the OP on
// :8080 with one statically-provisioned client. A production embedder
// runs the schema through their own migration tooling and persists
// the database where it belongs.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: SQLite via op/storeadapter/sql; production runs schema migrations through the embedder's tooling and persists the database where it belongs.
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
		op.WithCookieKey(keys.CookieKey),
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
