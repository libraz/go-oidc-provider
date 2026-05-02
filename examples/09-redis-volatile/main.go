//go:build example

// Example 09-redis-volatile is the canonical hot/cold deployment shape:
// MySQL (or any [op/storeadapter/sql] target) handles every durable
// substore, while Redis hosts the high-QPS volatile substores
// (Sessions, Interactions, ConsumedJTIs). Example 08 demonstrates the
// same composite wiring with inmem as a stand-in for Redis; this
// example swaps the stand-in for the real adapter and pairs the OP
// with an in-process RP so an embedder can drive a full Authorization
// Code + PKCE round-trip from a browser without external setup.
//
// # What lives where
//
// SQL durable backend (oidc_users, clients, codes, refresh tokens,
// grants, PAR, access tokens, IATs, RATs).
//
// Redis volatile backend:
//
//   - Sessions — browser session records (the OP does not coordinate
//     Session writes with token-endpoint commits, so a volatile cache
//     is the right tier)
//   - Interactions — short-lived UI state during login / consent
//   - ConsumedJTIs — DPoP and private_key_jwt replay protection
//
// The transactional cluster substores (AuthorizationCodes,
// RefreshTokens, Grants, PushedAuthRequests, AccessTokens) are
// deliberately routed to the SQL backend: the composite adapter
// rejects splitting them across backends because doing so would
// shatter the rotation-chain atomicity guarantee. Validation happens
// at composite.New time.
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
// Two listeners come up in the same process:
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
//     verified ID Token claims rendered as JSON. The "iss" claim
//     matches http://127.0.0.1:8080.
//
// # Running
//
// The example ships a docker-compose stack that runs all three
// services (mysql, redis, the OP+RP binary) on a private docker
// network. mysql and redis are not exposed to the host; only the OP
// container publishes 8080 and 9090 so the browser can drive the
// flow:
//
//	docker compose -f examples/09-redis-volatile/compose.yaml up -d --build
//	open http://127.0.0.1:9090/
//	# sign in as demo / demo, approve consent
//	docker compose -f examples/09-redis-volatile/compose.yaml down -v
//
// Image / engine versions (mysql:8.4, redis:7.4-alpine) match the
// testcontainers contract harness so adapter-level and example-level
// integration share a single engine matrix. REDIS_DEV_MODE=1 is
// baked into the compose service environment because the stack does
// not terminate TLS on the Redis container.
//
// To iterate on main.go without rebuilding the docker image, expose
// the engines temporarily by passing a compose override that adds
// host ports, run the example with `go run -tags example .`, and
// pass the matching MYSQL_HOST / REDIS_DSN env vars. The default
// compose.yaml deliberately omits host-port mapping so the demo
// path is conflict-free.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: composite (MySQL durable + Redis volatile); MYSQL_DSN / REDIS_DSN are env-var driven, production loads credentials from a secret manager and applies SQL migrations through dedicated tooling.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - User seed: the demo username / password are hard-coded; production embedders enrol users through their own management plane.
//   - rpkit: the RP code in examples/internal/rpkit is a demo wrapper, not a library.
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

	_ "github.com/go-sql-driver/mysql"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/composite"
	oidcredis "github.com/libraz/go-oidc-provider/op/storeadapter/redis"
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
	keys := devkeys.MustEphemeral("redis-volatile-1")

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

	// --- Demo user seed (durable backend) ---------------------------
	if err := seedUser(durable); err != nil {
		return fmt.Errorf("seed demo user: %w", err)
	}

	// --- Composite wiring -------------------------------------------
	// Every Kind in composite.TxClusterKinds resolves to durable via
	// WithDefault. Three volatile Kinds (Sessions, Interactions,
	// ConsumedJTIs) override to volatile via With(). composite.New
	// rejects any configuration that would split TxClusterKinds across
	// backends; Sessions is intentionally not in that set.
	storage, err := composite.New(
		composite.WithDefault(durable),
		composite.With(composite.Sessions, volatile),
		composite.With(composite.Interactions, volatile),
		composite.With(composite.ConsumedJTIs, volatile),
	)
	if err != nil {
		return fmt.Errorf("composite.New: %w", err)
	}

	// --- LoginFlow: password primary against the SQL UserPasswordStore
	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: durable.UserPasswords()},
	}

	// op.WithStaticClients seeds clients through composite.Store via
	// the optional ClientRegistry() probe (see the godoc on
	// composite.Store.ClientRegistry); seeding does not need to bypass
	// the composite anymore.
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

	// rpkit runs OIDC discovery synchronously, so wait until the OP
	// listener is up before constructing the RP.
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

func seedUser(durable *oidcsql.Store) error {
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
	return durable.PutUserWithPassword(context.Background(), user, demoUsername, hash)
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

// waitForIssuer polls iss + "/.well-known/openid-configuration" until
// it returns 200 or ctx is cancelled. The example boots the OP and
// the RP in the same process, so the RP's OIDC discovery runs as
// soon as the OP listener is ready.
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
