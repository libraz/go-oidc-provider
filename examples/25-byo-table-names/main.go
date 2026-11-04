//go:build example

// Example 25-byo-table-names shows how to graft the OP onto a database
// whose table names follow an existing application's convention instead
// of the adapter's bundled oidc_* defaults. Two options do it:
//
//   - oidcsql.WithTablePrefix("auth_") replaces the oidc_ prefix on every
//     table at once, including the migration version table
//     (auth_schema_migrations). It is the option to reach for first: one
//     value, no list to keep in step with the adapter's tables.
//   - oidcsql.WithNaming takes a map of logical record kind -> physical
//     table name and overrides single tables outright, on top of the
//     prefix. Here it renames only "users", to auth_accounts, the way an
//     embedder fits one table to a naming convention the prefix cannot
//     express. The "schema_migrations" key would rename the version table
//     the same way.
//
// The adapter validates every physical name against the SQL standard
// identifier grammar, rewrites the embedded DDL, and builds every query
// against the renamed tables. Column names stay fixed; an embedder that
// also needs custom columns implements the store interfaces directly (see
// example 24-byo-userstore and 26-byo-store-from-scratch).
//
// Run with:
//
//	(cd examples/25-byo-table-names && GOWORK=off go run -tags example .)
//
// The example applies the rewritten schema, logs the physical tables the
// adapter actually created, seeds one password user into the renamed users
// table, and serves the OP on :8080.
//
// Manual verification:
//
//  1. Start the example and read the "created tables:" log line. Every
//     table carries the auth_ prefix, none carries the bundled oidc_
//     prefix, the users table is auth_accounts rather than auth_users,
//     and auth_schema_migrations is the version table Migrate keeps.
//  2. Open http://127.0.0.1:8080/.well-known/openid-configuration to
//     confirm the OP serves normally from the renamed store.
//  3. Point a relying party at the OP and sign in as username "demo" /
//     password "demo". The credential is read back out of auth_accounts,
//     which is the rename taking effect on the read path rather than
//     only on the DDL.
//
// PRODUCTION CAVEATS:
//   - Keys: key derivation uses a hardcoded ephemeral value for the demo; production must derive the signing key from a vault / KMS.
//   - Store: the sqlite DSN here uses a local file; production uses Postgres / MySQL via op/storeadapter/sql, runs the rewritten schema through the embedder's migration tooling, and persists the database where it belongs.
//   - Naming: the prefix and the override are hard-coded here for clarity; production sources them from the embedder's schema convention.
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
	"sort"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

const (
	opAddr = ":8080"
	issuer = "http://127.0.0.1" + opAddr

	tablePrefix = "auth_"

	demoUsername = "demo"
	demoPassword = "demo"
	demoSubject  = "demo-user"
)

// naming overrides one table on top of the "auth_" prefix. Every table
// not listed keeps its prefixed default (auth_clients, auth_sessions, ...),
// and so does the version table. Unknown keys make oidcsql.New fail fast,
// so a typo here is caught at construction.
var naming = map[string]string{
	"users": "auth_accounts",
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	keys := devkeys.MustEphemeral("byo-table-names-1")

	dbPath := filepath.Join(os.TempDir(), "oidc-example-25.db")
	// The demo deletes its throwaway SQLite file on each run, so it always
	// starts from the current schema. Production embedders
	// track schema versions through their own migration tooling.
	_ = os.Remove(dbPath)
	dsn := "file:" + dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := databasesql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer func() { _ = db.Close() }()

	storage, err := oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithTablePrefix(tablePrefix), oidcsql.WithNaming(naming))
	if err != nil {
		return fmt.Errorf("oidcsql.New: %w", err)
	}
	// Migrate applies the migration files with the prefix and the override
	// already substituted; storage.Migrations() returns those same files for
	// embedders who drive migrations from their own tooling.
	if err := storage.Migrate(context.Background()); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	tables, err := listTables(context.Background(), db)
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}
	log.Printf("created tables: %s", strings.Join(tables, ", "))

	if err := seedUser(storage); err != nil {
		return fmt.Errorf("seed demo user: %w", err)
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(storage),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		// The password prompt reads the renamed auth_accounts table through
		// the adapter's store interface; the rename is invisible above
		// this line, which is the whole point of the naming options.
		op.WithProfile(profile.OAuth21),
		op.WithLoginFlow(op.LoginFlow{Primary: op.PrimaryPassword{Store: storage.UserPasswords()}}),
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

	log.Printf("OP backed by renamed SQLite tables listening on %s (issuer %s)", opAddr, issuer)
	log.Printf("demo user: username=%q password=%q (row lives in auth_accounts)", demoUsername, demoPassword)
	if err := serve.Listen(opAddr, mux, provider); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	return nil
}

// seedUser writes the demo credential through the adapter, which
// resolves the logical "users" kind to the physical auth_accounts table
// declared in the naming map above.
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

// listTables reads the physical table names back from sqlite_master so
// the demo can prove the rename took effect rather than asserting it
// from the configuration alone.
func listTables(ctx context.Context, db *databasesql.DB) ([]string, error) {
	rows, err := db.QueryContext(ctx,
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}
