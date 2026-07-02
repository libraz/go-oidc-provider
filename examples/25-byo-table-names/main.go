//go:build example

// Example 25-byo-table-names shows how to graft the OP onto a database
// whose table names follow an existing application's convention instead
// of the adapter's bundled oidc_* defaults. oidcsql.WithNaming takes a
// map of logical record kind -> physical table name; the adapter
// validates every physical name against the SQL standard identifier
// grammar, rewrites the embedded DDL, and builds every query against the
// renamed tables. Column names stay fixed — the adapter owns the column
// layout, and an embedder that also needs custom columns implements the
// store interfaces directly (see example 26-byo-store-from-scratch).
//
// Run with:
//
//	(cd examples/25-byo-table-names && go run -tags example .)
//
// The example renames all eighteen OP-internal tables under an "auth_"
// prefix, applies the rewritten schema, logs the physical tables the
// adapter actually created, and serves the OP on :8080.
//
// Manual verification:
//
//  1. Start the example and read the "created tables:" log line — every
//     table carries the auth_ prefix, none carry the bundled oidc_
//     prefix.
//  2. Open http://127.0.0.1:8080/.well-known/openid-configuration to
//     confirm the OP serves normally from the renamed store.
//
// PRODUCTION CAVEATS:
//   - Keys: key derivation uses a hardcoded ephemeral value for the demo; production must derive the signing key from a vault / KMS.
//   - Store: the sqlite DSN here uses a local file; production uses Postgres / MySQL via op/storeadapter/sql, runs the rewritten schema through the embedder's migration tooling, and persists the database where it belongs.
//   - Naming: physical names are hard-coded here for clarity; production sources them from the embedder's schema convention.
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
	"sort"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// naming maps every logical record kind WithNaming accepts onto a
// physical table name under this embedder's "auth_" convention. Listing
// all eighteen keys makes it explicit that the rename covers the whole
// OP-internal surface, not just the clients table. Unknown keys make
// oidcsql.New fail fast, so a typo here is caught at construction time.
var naming = map[string]string{
	"clients":                    "auth_clients",
	"authorization_codes":        "auth_codes",
	"refresh_tokens":             "auth_refresh_tokens",
	"access_tokens":              "auth_access_tokens",
	"opaque_access_tokens":       "auth_opaque_access_tokens",
	"grant_revocations":          "auth_grant_revocations",
	"revoked_jtis":               "auth_revoked_jtis",
	"grants":                     "auth_grants",
	"sessions":                   "auth_sessions",
	"par_records":                "auth_par_records",
	"interactions":               "auth_interactions",
	"consumed_jtis":              "auth_consumed_jtis",
	"users":                      "auth_users",
	"initial_access_tokens":      "auth_initial_access_tokens",
	"registration_access_tokens": "auth_registration_access_tokens",
	"op_metadata":                "auth_op_metadata",
	"device_codes":               "auth_device_codes",
	"ciba_requests":              "auth_ciba_requests",
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	keys := devkeys.MustEphemeral("byo-table-names-1")

	dbPath := filepath.Join(os.TempDir(), "oidc-example-25.db")
	// Pre-v1 schemas can evolve between checkouts; remove any prior file
	// so a re-run never collides with a stale DDL. Production embedders
	// track schema versions through their own migration tooling.
	_ = os.Remove(dbPath)
	dsn := "file:" + dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := databasesql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer func() { _ = db.Close() }()

	storage, err := oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithNaming(naming))
	if err != nil {
		return fmt.Errorf("oidcsql.New: %w", err)
	}
	if err := storage.Migrate(context.Background()); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	tables, err := listTables(context.Background(), db)
	if err != nil {
		return fmt.Errorf("list tables: %w", err)
	}
	log.Printf("created tables: %s", strings.Join(tables, ", "))

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

	log.Println("OP backed by renamed SQLite tables listening on :8080 (issuer https://op.example.com)")
	if err := serve.Listen(":8080", mux); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	return nil
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
