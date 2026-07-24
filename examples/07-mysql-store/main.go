//go:build example

// Example 07-mysql-store wires the SQL storage adapter
// (op/storeadapter/sql) into a runnable Provider against a MySQL
// engine. Every substore — durable (clients, codes, refresh tokens,
// grants, access tokens, users, IATs, RATs) and volatile (Sessions,
// Interactions, ConsumedJTIs) — lives in the same MySQL database;
// the example complements 09-redis-volatile, which routes the
// volatile substores to Redis through op/storeadapter/composite.
//
// The example pairs the OP with an in-process RP (built on
// examples/internal/rpkit) so an embedder can drive a full
// Authorization Code + PKCE round-trip from a browser without any
// external setup beyond the bundled docker stack.
//
// # What you can verify
//
// Two listeners come up in the same Go process:
//
//   - :8080 — the OP, with issuer http://127.0.0.1:8080, one seeded
//     password user (demo / demo), and one statically-registered
//     public client whose redirect URI points at the RP.
//   - :9090 — the RP, built from examples/internal/rpkit. It exposes
//     /, /login, /callback, /me.
//
// Manual verification:
//
//  1. Open http://127.0.0.1:9090/ — RP landing page.
//  2. Click "Log in via the OP" — the browser is redirected to the OP.
//  3. Sign in as username "demo" / password "demo".
//  4. Approve the consent prompt.
//  5. The browser ends up at http://127.0.0.1:9090/me with the
//     verified ID Token claims rendered as JSON.
//
// # Configuration
//
// Driven by environment variables so the example doubles as a working
// reference for production wiring:
//
//	MYSQL_DSN   full DSN, takes precedence over the host/user/pass triple
//	MYSQL_HOST  default 127.0.0.1:3306
//	MYSQL_USER  default oidc
//	MYSQL_PASS  default oidc
//	MYSQL_DB    default oidc
//
// # Running
//
// The example ships a docker-compose stack that runs both MySQL and
// the OP+RP binary on a private docker network. MySQL is not exposed
// to the host; only the OP container publishes 8080 and 9090 so the
// browser can drive the flow:
//
//	docker compose -f examples/07-mysql-store/compose.yaml up -d --build
//	open http://127.0.0.1:9090/
//	# sign in as demo / demo, approve consent
//	docker compose -f examples/07-mysql-store/compose.yaml down -v
//
// Engine version (mysql:8.4) matches the testcontainers contract
// harness so adapter-level and example-level integration share a
// single matrix.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: MySQL via op/storeadapter/sql; DSN is env-var driven, production loads it from a secret manager and applies migrations through dedicated tooling. Startup diagnostics use a parsed endpoint label and never print DSN credentials.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - User seed: the demo username / password are hard-coded; production embedders enrol users through their own management plane.
//   - Connection pool: the values below are conservative production defaults; tune them against your engine's max_connections and the OP's expected concurrency.
package main

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

const (
	opAddr      = ":8080"
	rpAddr      = ":9090"
	issuer      = "http://127.0.0.1" + opAddr
	rpBase      = "http://127.0.0.1" + rpAddr
	clientID    = "demo-rp"
	redirectURI = rpBase + "/callback"

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
	keys := devkeys.MustEphemeral("mysql-store-1")

	dsn := mysqlDSN()
	mysqlEndpoint, err := redactedMySQLDSN(dsn)
	if err != nil {
		return errors.New("parse mysql DSN: invalid DSN")
	}
	db, err := databasesql.Open("mysql", dsn)
	if err != nil {
		return mysqlConnectionError("open", mysqlEndpoint, err)
	}
	defer func() { _ = db.Close() }()

	// Connection-pool tuning is the embedder's responsibility. The
	// adapter does NOT call SetMaxOpenConns / SetMaxIdleConns itself
	// (see oidcsql.New godoc).
	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)

	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		return mysqlConnectionError("ping", mysqlEndpoint, err)
	}

	storage, err := oidcsql.New(db, oidcsql.MySQL())
	if err != nil {
		return fmt.Errorf("oidcsql.New: %w", err)
	}
	if err := storage.Migrate(context.Background()); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	log.Printf("mysql store ready (%s)", mysqlEndpoint)

	if err := seedUser(storage); err != nil {
		return fmt.Errorf("seed demo user: %w", err)
	}

	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: storage.UserPasswords()},
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(storage),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithLoginFlow(flow),
		op.WithStaticClients(op.PublicClient{
			ID:           clientID,
			RedirectURIs: []string{redirectURI},
			Scopes:       []string{"openid", "profile", "email"},
		}),
	)
	if err != nil {
		return fmt.Errorf("op.New: %w", err)
	}

	opMux := http.NewServeMux()
	opMux.Handle("/", provider)

	opErrCh := make(chan error, 1)
	go func() {
		log.Printf("OP listening on %s (issuer %s)", opAddr, issuer)
		opErrCh <- serve.Listen(opAddr, opMux)
	}()

	rpCtx, rpCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer rpCancel()
	if err := waitForIssuer(rpCtx, issuer); err != nil {
		return err
	}

	rp, err := rpkit.New(context.Background(), rpkit.Options{
		Issuer:      issuer,
		ClientID:    clientID,
		RedirectURL: redirectURI,
		Scopes:      []string{"openid", "profile", "email"},
	})
	if err != nil {
		return fmt.Errorf("rpkit.New: %w", err)
	}

	rpMux := http.NewServeMux()
	rpMux.Handle("/", rp.Handler())

	log.Printf("RP listening on %s — open %s/", rpAddr, rpBase)
	log.Printf("demo user: username=%q password=%q", demoUsername, demoPassword)

	rpErrCh := make(chan error, 1)
	go func() { rpErrCh <- serve.Listen(rpAddr, rpMux) }()

	select {
	case err := <-opErrCh:
		return err
	case err := <-rpErrCh:
		return err
	}
}

func seedUser(storage *oidcsql.Store) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return err
	}
	user := &store.User{
		Subject: demoSubject,
		Claims: map[string]any{
			"name":  "Demo User",
			"email": "demo@example.com",
		},
	}
	return storage.PutUserWithPassword(context.Background(), user, demoUsername, hash)
}

func mysqlDSN() string {
	if dsn := os.Getenv("MYSQL_DSN"); dsn != "" {
		return dsn
	}
	host := envOr("MYSQL_HOST", "127.0.0.1:3306")
	user := envOr("MYSQL_USER", "oidc")
	pass := envOr("MYSQL_PASS", "oidc")
	dbname := envOr("MYSQL_DB", "oidc")
	return fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true&charset=utf8mb4&loc=UTC",
		user, pass, host, dbname)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// redactedMySQLDSN parses the driver-native format and returns only the
// network endpoint and database name. It deliberately omits user info and
// parameters, either of which may contain credentials.
func redactedMySQLDSN(dsn string) (string, error) {
	cfg, err := mysqldriver.ParseDSN(dsn)
	if err != nil {
		return "", errors.New("invalid MySQL DSN")
	}
	endpoint := cfg.Net + "(" + cfg.Addr + ")"
	if cfg.DBName != "" {
		endpoint += "/" + cfg.DBName
	}
	return endpoint, nil
}

// mysqlConnectionError keeps startup diagnostics useful without forwarding
// driver text. MySQL authentication errors may quote the attempted username;
// retaining only the numeric server code prevents that credential disclosure
// while mysqlConnectionFailure.Unwrap preserves the cause for errors.Is/As.
func mysqlConnectionError(action, endpoint string, err error) error {
	failure := &mysqlConnectionFailure{
		action:   action,
		endpoint: endpoint,
		cause:    err,
	}
	var serverErr *mysqldriver.MySQLError
	if errors.As(err, &serverErr) {
		failure.serverCode = serverErr.Number
		failure.hasServerCode = true
	}
	return failure
}

type mysqlConnectionFailure struct {
	action        string
	endpoint      string
	cause         error
	serverCode    uint16
	hasServerCode bool
}

func (e *mysqlConnectionFailure) Error() string {
	if e.hasServerCode {
		return fmt.Sprintf("%s mysql (%s): server error %d", e.action, e.endpoint, e.serverCode)
	}
	return fmt.Sprintf("%s mysql (%s): connection failed", e.action, e.endpoint)
}

func (e *mysqlConnectionFailure) Unwrap() error {
	return e.cause
}

// waitForIssuer polls iss + "/.well-known/openid-configuration" until
// it returns 200 or ctx is cancelled.
func waitForIssuer(ctx context.Context, iss string) error {
	url := iss + "/.well-known/openid-configuration"
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("waitForIssuer: timeout polling " + url)
		case <-tick.C:
		}
	}
}
