//go:build example

// Example 07-mysql-store wires the SQL storage adapter (op/storeadapter/sql)
// into a runnable Provider against a MySQL 8.0 / MariaDB 10.5+ engine. The
// example complements 06-sql-store, which targets SQLite, by showing the
// production-shaped DSN, the connection-pool tuning the adapter explicitly
// does NOT touch, and the env-var seam embedders use to pin host/port and
// credentials without recompiling.
//
// Run with:
//
//	go run -tags example ./examples/07-mysql-store
//
// The example honours the following environment variables (all optional):
//
//	MYSQL_DSN  — full database/sql DSN. When set, the example uses it
//	             verbatim and ignores MYSQL_HOST/USER/PASS/DB.
//	MYSQL_HOST — host:port (default 127.0.0.1:3306)
//	MYSQL_USER — username   (default oidc)
//	MYSQL_PASS — password   (default oidc)
//	MYSQL_DB   — database   (default oidc)
//
// The example boots the OP on :8080 with one statically-provisioned client.
// A production embedder applies the schema through their own migration
// tooling (Atlas, Goose, Flyway, …) rather than calling Migrate at startup.
package main

import (
	"context"
	databasesql "database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	keys := devkeys.MustEphemeral("mysql-store-1")

	dsn := mysqlDSN()
	db, err := databasesql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("open mysql: %w", err)
	}
	defer func() { _ = db.Close() }()

	// Connection-pool tuning is the embedder's responsibility. The
	// adapter does NOT call SetMaxOpenConns / SetMaxIdleConns itself
	// (see oidcsql.New godoc). The values below are conservative
	// production defaults; tune them against your engine's
	// max_connections and the OP's expected concurrency.
	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)

	// Validate the connection up front so a misconfigured DSN
	// surfaces here rather than at the first /authorize hit.
	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		return fmt.Errorf("ping mysql (%s): %w", dsn, err)
	}

	storage, err := oidcsql.New(db, oidcsql.MySQL())
	if err != nil {
		return fmt.Errorf("oidcsql.New: %w", err)
	}
	if err := storage.Migrate(context.Background()); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	log.Printf("mysql store ready (dsn redacted)")

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

	log.Println("OP backed by MySQL listening on :8080 (issuer https://op.example.com)")
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	return nil
}

// mysqlDSN assembles the database/sql DSN from environment variables.
// Embedders typically build their DSN from a secret manager rather
// than env vars; this example prefers MYSQL_DSN verbatim when set so
// production patterns (Vault, AWS Secrets Manager, …) drop in
// directly.
func mysqlDSN() string {
	if dsn := os.Getenv("MYSQL_DSN"); dsn != "" {
		return dsn
	}
	host := envOr("MYSQL_HOST", "127.0.0.1:3306")
	user := envOr("MYSQL_USER", "oidc")
	pass := envOr("MYSQL_PASS", "oidc")
	dbname := envOr("MYSQL_DB", "oidc")
	// parseTime=true makes DATETIME / TIMESTAMP scan into time.Time,
	// which the adapter's encoding helpers expect. charset=utf8mb4
	// matches the bundled DDL (which uses utf8mb4 for opaque
	// identifier columns).
	return fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true&charset=utf8mb4&loc=UTC",
		user, pass, host, dbname)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
