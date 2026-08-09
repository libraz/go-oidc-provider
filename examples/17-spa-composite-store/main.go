//go:build example

// Example 17-spa-composite-store is the deployment shape most web
// applications actually want, assembled in one place: a single-page
// application owns the login and consent screens, MySQL holds the
// durable records, and Redis holds the volatile ones.
//
// The two halves already have examples of their own —
// examples/10-react-login for the SPA seam, examples/09-redis-volatile
// for the hot/cold storage split — and they are genuinely independent:
// the interaction driver has no opinion about where records live, and
// the store has none about what renders the login screen. That
// independence is the point, but it also means neither example shows
// what the combination looks like, and the combination is what gets
// deployed. This one exists so nobody has to guess whether the two
// compose.
//
// # What lives where
//
// MySQL, via op/storeadapter/sql, holds the durable substores: users,
// clients, authorization codes, refresh tokens, grants, pushed
// authorization requests, access tokens, and registration tokens.
//
// Redis, via op/storeadapter/redis, holds the volatile ones:
//
//   - Sessions — browser session records
//   - Interactions — the short-lived state of a login / consent
//     ceremony, which is exactly what the SPA is reading and writing
//     over the JSON state endpoints
//   - ConsumedJTIs — DPoP and private_key_jwt replay protection
//
// Interactions on Redis is the pairing worth noticing. Every screen
// the SPA renders is one read of that substore, and every submission
// is one write, so the SPA seam is the heaviest user of the fastest
// tier. The transactional cluster (authorization codes, refresh
// tokens, grants, PAR, access tokens) stays on MySQL because
// composite.New refuses to split it — spreading those across backends
// would break rotation-chain atomicity.
//
// # What the SPA owns, and what it does not
//
// op.WithSPAUI replaces the bundled server-rendered driver. The OP
// stops emitting HTML for login and consent and serves the SPA bundle
// at /login plus a JSON state envelope the bundle drives. What the OP
// does NOT give up is the decision of which factor comes next, or the
// validation of anything submitted: the SPA renders whatever the
// envelope describes and posts back a submission, and an SPA that
// invents its own steps gets them rejected.
//
// The bundle here is the same one examples/10-react-login ships. It is
// deliberately dependency-free hand-written JavaScript rather than a
// framework build, so the example has no npm step and the state
// machine it implements stays readable.
//
// # Configuration
//
// Environment variables, so this doubles as production wiring:
//
//	MYSQL_DSN          full DSN, takes precedence over the triple below
//	MYSQL_HOST         default 127.0.0.1:3306
//	MYSQL_USER         default root
//	MYSQL_PASS         default empty
//	MYSQL_DB           default oidc
//	REDIS_DSN          rediss:// URL, default rediss://localhost:6379/0
//	REDIS_PASSWORD     password for AUTH
//	REDIS_USERNAME     ACL username (optional)
//	REDIS_DEV_MODE     "1" accepts a plaintext redis:// DSN. Local only.
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP, issuer http://127.0.0.1:8080, SPA bundle at
//     /login, one seeded password user (demo / demo).
//   - :9090 — the RP, exposing /, /login, /callback, /me.
//
// # Running
//
// The bundled stack runs MySQL, Redis, and the OP+RP binary on a
// private docker network. Only the OP container publishes ports:
//
//	docker compose -f examples/17-spa-composite-store/compose.yaml up -d --build
//	open http://127.0.0.1:9090/
//	# sign in as demo / demo, approve consent
//	docker compose -f examples/17-spa-composite-store/compose.yaml down -v
//
// Manual verification:
//
//  1. Open http://127.0.0.1:9090/ — the RP landing page.
//  2. Click "Log in via the OP". The browser lands on /login and the
//     SPA renders the password screen from the JSON envelope.
//  3. Sign in as demo / demo, then approve consent — also SPA-rendered.
//  4. The browser ends at /me with the verified ID Token claims.
//
// Restarting the OP container invalidates every in-flight session:
// the signing and cookie keys are ephemeral. The MySQL volume
// survives, so the seeded user and any registered client do not need
// re-creating.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: composite (MySQL durable + Redis volatile); credentials come from env vars here and from a secret manager in production, and SQL migrations run through dedicated tooling rather than at boot.
//   - Listener: plain HTTP; front behind TLS-terminating ingress. The SPA seam makes this more pressing than usual — the interaction state endpoints carry the CSRF token the ceremony depends on.
//   - Redis: the compose stack speaks plaintext redis:// and sets REDIS_DEV_MODE=1 to make the adapter accept it. Production terminates TLS (rediss://).
//   - User seed: the demo credentials are hard-coded; production embedders enrol users through their own management plane.
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

	mysqldriver "github.com/go-sql-driver/mysql"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/examples/internal/webui"
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
	clientID    = "demo-spa"
	redirectURI = rpBase + "/callback"

	demoUsername = "demo"
	demoPassword = "demo"
	demoSubject  = "demo-user"

	staticDir = webui.StaticDir
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if _, err := os.Stat(staticDir); err != nil {
		return errors.New("StaticDir " + staticDir + " missing — run from the example directory so the shared SPA bundle resolves")
	}

	keys := devkeys.MustEphemeral("spa-composite-1")

	durable, closeDurable, err := openDurable()
	if err != nil {
		return err
	}
	defer closeDurable()

	redisDSN := envOr("REDIS_DSN", "rediss://localhost:6379/0")
	volatile, err := openVolatile(redisDSN)
	if err != nil {
		return fmt.Errorf("oidcredis.New: %w", err)
	}
	defer func() { _ = volatile.Close() }()
	log.Printf("volatile store: redis (%s)", oidcredis.RedactedDSN(redisDSN))

	if err := seedUser(durable); err != nil {
		return fmt.Errorf("seed demo user: %w", err)
	}

	// Interactions is the substore the SPA exercises on every screen,
	// which is the reason it belongs on the volatile tier alongside
	// Sessions and ConsumedJTIs. Everything else defaults to MySQL;
	// composite.New rejects any routing that would split the
	// transactional cluster.
	storage, err := composite.New(
		composite.WithDefault(durable),
		composite.With(composite.Sessions, volatile),
		composite.With(composite.Interactions, volatile),
		composite.With(composite.ConsumedJTIs, volatile),
	)
	if err != nil {
		return fmt.Errorf("composite.New: %w", err)
	}

	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: durable.UserPasswords()},
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(storage),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithLoginFlow(flow),
		// The SPA bundle replaces the bundled HTML driver. Login and
		// consent are rendered from the JSON state envelope; the OP
		// still decides the step order and validates every submission.
		op.WithSPAUI(op.SPAUI{
			LoginMount: "/login",
			StaticDir:  staticDir,
		}),
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
		log.Printf("OP listening on %s (issuer %s, SPA at /login)", opAddr, issuer)
		opErrCh <- serve.Listen(opAddr, opMux)
	}()

	// rpkit runs OIDC discovery synchronously, so wait for the OP
	// listener before constructing the RP.
	rpCtx, rpCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer rpCancel()
	if err := serve.WaitForIssuer(rpCtx, issuer); err != nil {
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

// openDurable brings up the MySQL-backed durable store and applies the
// adapter's migrations. The returned close function releases the pool
// whichever way run() exits.
func openDurable() (*oidcsql.Store, func(), error) {
	dsn := mysqlDSN()
	endpoint, err := redactedMySQLDSN(dsn)
	if err != nil {
		return nil, nil, errors.New("parse mysql DSN: invalid DSN")
	}
	db, err := databasesql.Open("mysql", dsn)
	if err != nil {
		return nil, nil, mysqlConnectionError("open", endpoint, err)
	}
	closeDB := func() { _ = db.Close() }
	db.SetMaxOpenConns(50)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetConnMaxIdleTime(5 * time.Minute)

	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		closeDB()
		return nil, nil, mysqlConnectionError("ping", endpoint, err)
	}

	durable, err := oidcsql.New(db, oidcsql.MySQL())
	if err != nil {
		closeDB()
		return nil, nil, fmt.Errorf("oidcsql.New: %w", err)
	}
	// Migrate is a development shortcut. Production deployments run
	// durable.Schema() through their own migration tooling instead.
	if err := durable.Migrate(context.Background()); err != nil {
		closeDB()
		return nil, nil, fmt.Errorf("mysql migrate: %w", err)
	}
	log.Printf("durable store: mysql (%s)", endpoint)
	return durable, closeDB, nil
}

func openVolatile(dsn string) (*oidcredis.Store, error) {
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
	host := envOr("MYSQL_HOST", "127.0.0.1:3306")
	user := envOr("MYSQL_USER", "root")
	pass := os.Getenv("MYSQL_PASS")
	dbName := envOr("MYSQL_DB", "oidc")
	return fmt.Sprintf("%s:%s@tcp(%s)/%s?parseTime=true&charset=utf8mb4&loc=UTC", user, pass, host, dbName)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// redactedMySQLDSN parses the driver-native format and returns only
// the network endpoint and database name, omitting user info and
// parameters — either may carry credentials.
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

// mysqlConnectionError keeps startup diagnostics useful without
// forwarding driver text: MySQL authentication errors may quote the
// attempted username, so only the numeric server code is retained.
// Unwrap preserves the cause for errors.Is / errors.As.
func mysqlConnectionError(action, endpoint string, err error) error {
	failure := &mysqlConnectionFailure{action: action, endpoint: endpoint, cause: err}
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

func (e *mysqlConnectionFailure) Unwrap() error { return e.cause }
