//go:build example

// Example 09-redis-volatile is the canonical hot/cold deployment shape:
// MySQL (or any [op/storeadapter/sql] target) handles every durable
// substore, while Redis hosts the high-QPS volatile substores
// (Interactions, ConsumedJTIs). Example 08 demonstrates the same
// composite wiring with inmem as a stand-in for Redis; this example
// swaps the stand-in for the real adapter.
//
// # What lives where
//
// SQL durable backend (oidc_users, clients, codes, refresh tokens,
// grants, sessions, PAR, access tokens, IATs, RATs).
//
// Redis volatile backend:
//
//   - Interactions — short-lived UI state during login / consent
//   - ConsumedJTIs — DPoP and private_key_jwt replay protection
//
// The transactional cluster substores (AuthorizationCodes,
// RefreshTokens, Grants, Sessions, PushedAuthRequests, AccessTokens)
// are deliberately routed to the SQL backend: the composite adapter
// rejects splitting them across backends because doing so would
// shatter the rotation-chain atomicity guarantee. Validation happens at
// composite.New time.
//
// # Configuration
//
// Driven by environment variables so the example doubles as a working
// reference for production wiring:
//
//	MYSQL_DSN          full DSN, takes precedence over the host/user/pass triple
//	MYSQL_HOST         default 127.0.0.1:3306
//	MYSQL_USER         default root
//	MYSQL_PASS         default empty
//	MYSQL_DB           default oidc
//	REDIS_DSN          rediss:// URL, default rediss://localhost:6379/0
//	REDIS_PASSWORD     password for AUTH (required unless dev mode)
//	REDIS_USERNAME     ACL username (optional)
//	REDIS_DEV_MODE     when "1", enables WithDevModeAllowPlaintext so
//	                   redis:// (plaintext) DSNs are accepted. Local
//	                   development only.
//
// Run with:
//
//	go run -tags example ./examples/09-redis-volatile
//
// Pre-flight: a MySQL 8.0+ instance and a Redis 7+ instance must be
// reachable from the host. The example does not boot containers; that
// responsibility belongs to your local docker-compose or the operator.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	databasesql "database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/composite"
	oidcredis "github.com/libraz/go-oidc-provider/op/storeadapter/redis"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate signing key: %w", err)
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		return fmt.Errorf("generate cookie key: %w", err)
	}

	// --- Durable backend: SQL adapter against MySQL ----------------
	dsn := mysqlDSN()
	db, err := databasesql.Open("mysql", dsn)
	if err != nil {
		return fmt.Errorf("open mysql: %w", err)
	}
	defer func() { _ = db.Close() }()
	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)

	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		return fmt.Errorf("ping mysql: %w (DSN host=%s)", err, mustEnv("MYSQL_HOST", "127.0.0.1:3306"))
	}

	durable, err := oidcsql.New(db, oidcsql.MySQL())
	if err != nil {
		return fmt.Errorf("oidcsql.New: %w", err)
	}
	if err := durable.Migrate(context.Background()); err != nil {
		return fmt.Errorf("mysql migrate: %w", err)
	}
	log.Printf("durable store: mysql (%s)", maskedDSN(dsn))

	// --- Volatile backend: Redis adapter ----------------------------
	volatile, err := newRedis()
	if err != nil {
		return fmt.Errorf("oidcredis.New: %w", err)
	}
	defer func() { _ = volatile.Close() }()
	log.Printf("volatile store: redis (%s)", os.Getenv("REDIS_DSN"))

	// --- Static client seeding --------------------------------------
	// composite.Store deliberately does NOT implement
	// store.ClientRegistry directly (see the godoc on
	// composite.Store.ClientRegistry — exposing the interface would
	// hide the case where the routed Clients backend is read-only).
	// op.WithStaticClients does a type assertion against the supplied
	// store, so seeding goes against the SQL adapter directly, before
	// composite wraps it. Same pattern as example 08.
	seed := &store.Client{
		ID:           "demo-spa",
		RedirectURIs: []string{"https://rp.example.com/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"openid", "profile", "email"},
	}
	if err := durable.RegisterClient(context.Background(), seed); err != nil {
		if !errors.Is(err, store.ErrAlreadyExists) {
			return fmt.Errorf("seed demo-spa: %w", err)
		}
	}

	// --- Composite wiring -------------------------------------------
	// Every Kind in composite.TxClusterKinds resolves to durable via
	// WithDefault. Two volatile Kinds (Interactions, ConsumedJTIs)
	// override to volatile via With(). composite.New rejects any
	// configuration that would split TxClusterKinds across backends.
	storage, err := composite.New(
		composite.WithDefault(durable),
		composite.With(composite.Interactions, volatile),
		composite.With(composite.ConsumedJTIs, volatile),
	)
	if err != nil {
		return fmt.Errorf("composite.New: %w", err)
	}

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(storage),
		op.WithKeyset(op.Keyset{{KeyID: "redis-1", Signer: priv}}),
		op.WithCookieKey(cookieKey),
	)
	if err != nil {
		return fmt.Errorf("op.New: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("OP backed by composite (mysql + redis) listening on :8080 (issuer https://op.example.com)")
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

func mysqlDSN() string {
	if dsn := os.Getenv("MYSQL_DSN"); dsn != "" {
		return dsn
	}
	host := mustEnv("MYSQL_HOST", "127.0.0.1:3306")
	user := mustEnv("MYSQL_USER", "root")
	pass := os.Getenv("MYSQL_PASS")
	dbName := mustEnv("MYSQL_DB", "oidc")
	return fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true&charset=utf8mb4&loc=UTC", user, pass, host, dbName)
}

func newRedis() (*oidcredis.Store, error) {
	dsn := mustEnv("REDIS_DSN", "rediss://localhost:6379/0")
	opts := []oidcredis.Option{
		oidcredis.WithDSN(dsn),
		oidcredis.WithRedisAuth(os.Getenv("REDIS_USERNAME"), os.Getenv("REDIS_PASSWORD")),
	}
	if os.Getenv("REDIS_DEV_MODE") == "1" {
		opts = append(opts, oidcredis.WithDevModeAllowPlaintext(func(msg string) {
			log.Println("⚠️  " + msg)
		}))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return oidcredis.New(ctx, opts...)
}

func mustEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// maskedDSN strips the password from a MySQL DSN for safe logging.
// The DSN format is user:pass@tcp(host:port)/db?params.
func maskedDSN(dsn string) string {
	at := -1
	colon := -1
	for i := range len(dsn) {
		if dsn[i] == ':' && colon == -1 {
			colon = i
		}
		if dsn[i] == '@' {
			at = i
			break
		}
	}
	if at == -1 || colon == -1 || colon >= at {
		return dsn
	}
	return dsn[:colon+1] + "***" + dsn[at:]
}
