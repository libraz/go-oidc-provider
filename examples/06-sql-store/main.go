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
//	(cd examples/06-sql-store && GOWORK=off go run -tags example .)
//
// The example creates a fresh database file under the OS temp
// directory, applies the embedded v1 schema, seeds one password user
// into the adapter's users table, and serves the OP on :8080 with one
// statically-provisioned client. A production embedder runs the schema
// through their own migration tooling, persists the database where it
// belongs, and enrols users through their own management plane.
//
// The login flow reads its credentials straight off the SQL adapter
// (storage.UserPasswords()), so the same database the OP stores codes
// and grants in also answers the password prompt.
//
// Manual verification:
//
//  1. Start the example and note the "sqlite store at ..." log line.
//  2. Open http://127.0.0.1:8080/.well-known/openid-configuration
//     to confirm the OP is serving from the SQL-backed store.
//  3. Point a relying party at the OP and sign in as username "demo" /
//     password "demo" — the credentials live in the SQLite file, so
//     they survive for as long as it does.
//  4. Inspect the logged SQLite path if you want to see the v1
//     schema tables the adapter created for the demo database.
//
// PRODUCTION CAVEATS:
//   - Keys: key derivation uses a hardcoded ephemeral value for the demo; production must derive the signing key from a vault / KMS.
//   - Store: the sqlite DSN here uses a local file; production uses Postgres / MySQL via op/storeadapter/sql, runs schema migrations through the embedder's tooling, and persists the database where it belongs.
//   - DSN: the DSN string contains credentials; production should source it from a secret manager (Vault / AWS Secrets Manager / GCP Secret Manager) rather than hard-coding it next to the binary.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - User seed: the demo username / password are hard-coded; production embedders enrol users through their own management plane.
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
	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

const (
	opAddr = ":8080"
	issuer = "http://127.0.0.1" + opAddr

	demoUsername = "demo"
	demoPassword = "demo"
	demoSubject  = "demo-user"
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
	// Migrate is a development shortcut. Production deployments run
	// storage.Schema() through their own migration tooling instead.
	if err := storage.Migrate(context.Background()); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	log.Printf("sqlite store at %s", dbPath)

	if err := seedUser(storage); err != nil {
		return fmt.Errorf("seed demo user: %w", err)
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(storage),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		// The adapter's users table backs the password prompt: the same
		// SQLite file holds the credential, the session, and every token
		// record the flow goes on to write.
		op.WithLoginFlow(op.LoginFlow{
			Primary: op.PrimaryPassword{Store: storage.UserPasswords()},
		}),
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

	log.Printf("OP backed by SQLite listening on %s (issuer %s)", opAddr, issuer)
	log.Printf("demo user: username=%q password=%q", demoUsername, demoPassword)
	if err := serve.Listen(opAddr, mux); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	return nil
}

// seedUser writes the demo credential through the adapter's own
// PutUserWithPassword helper, so the record lands in the same users
// table the login flow reads back at prompt time.
func seedUser(storage *oidcsql.Store) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return err
	}
	return storage.PutUserWithPassword(context.Background(), &store.User{
		Subject: demoSubject,
		Claims: map[string]any{
			"name":  "Demo User",
			"email": "demo@example.com",
		},
	}, demoUsername, hash)
}
