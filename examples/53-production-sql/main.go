//go:build example

// Example 53 is the production wiring checklist for a SQL-backed OP in
// one place, split by concern so each file can be lifted on its own:
//
//   - main.go: configuration from the environment, schema check, the
//     reloadable handler, SIGHUP reload, the retention sweep and a
//     graceful shutdown.
//   - keys.go: the signing key and cookie keys read from a key directory.
//   - users.go: an existing users table with bcrypt hashes behind
//     [op.PrimaryPassword], rewritten as argon2id on each user's next login.
//   - clients.go: the static clients and the sync-clients admin command.
//
// SQLite is the default so the example runs without a database server.
// A deployment points it at MySQL or PostgreSQL instead: import the
// driver (github.com/go-sql-driver/mysql or github.com/jackc/pgx/v5/stdlib),
// open the DSN with it, and pass oidcsql.MySQL() or oidcsql.Postgres() to
// oidcsql.New. The users table queries in users.go use "?" placeholders,
// which PostgreSQL spells $1.
//
// Environment:
//
//	EXAMPLE53_ADDR      listen address (default 127.0.0.1:8080)
//	EXAMPLE53_ISSUER    issuer URL (default http://<EXAMPLE53_ADDR>; https behind the ingress in production)
//	EXAMPLE53_KEYS_DIR  key directory (default <os temp dir>/example53-keys)
//	EXAMPLE53_DSN       modernc.org/sqlite DSN (default a file in the os temp dir)
//	EXAMPLE53_MIGRATE   1 applies the OP schema and creates the demo users table (development only)
//
// Without EXAMPLE53_MIGRATE the process only validates the schema, so the
// database role needs no CREATE privilege. Production applies the DDL
// (schema/<dialect>/v1.sql in op/storeadapter/sql) through its own
// migration tool.
//
// Manual verification:
//
//  1. First run: (cd examples/53-production-sql && EXAMPLE53_MIGRATE=1 GOWORK=off go run -tags example .)
//     The log names the generated key directory; the database is
//     example53.db in the os temp dir.
//  2. Open http://127.0.0.1:8080/oidc/auth?response_type=code&client_id=production-sql-rp&redirect_uri=http://127.0.0.1:8081/callback&scope=openid%20profile%20email&state=s&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
//     and sign in as alice@example.com / alice-password. The log reports
//     that alice's bcrypt hash was rewritten.
//  3. sqlite3 <database file> "SELECT email, substr(password_hash, 1, 10) FROM app_users"
//     shows $argon2id$ for alice and still $2a$ for bob.
//  4. Rotate the cookie key: mv cookie.key cookie-retiring.key, write a new
//     cookie.key with "openssl rand -hex 32", then kill -HUP <pid>. The log
//     reports the reload and alice's session survives it.
//  5. Stop the server, edit the client in clients.go, and run
//     (cd examples/53-production-sql && GOWORK=off go run -tags example . sync-clients)
//     before starting it again; without the sync, startup refuses the edit.
package main

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/op"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

type config struct {
	addr, issuer, keysDir, dsn string
	migrate                    bool
}

func loadConfig() config {
	addr := envOr("EXAMPLE53_ADDR", "127.0.0.1:8080")
	dbPath := filepath.Join(os.TempDir(), "example53.db")
	return config{
		addr:    addr,
		issuer:  envOr("EXAMPLE53_ISSUER", "http://"+addr),
		keysDir: envOr("EXAMPLE53_KEYS_DIR", filepath.Join(os.TempDir(), "example53-keys")),
		dsn:     envOr("EXAMPLE53_DSN", "file:"+dbPath+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"),
		migrate: os.Getenv("EXAMPLE53_MIGRATE") == "1",
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	syncOnly := len(args) == 1 && args[0] == "sync-clients"
	if len(args) > 0 && !syncOnly {
		return fmt.Errorf("unknown arguments %q; the only command is sync-clients", args)
	}
	cfg := loadConfig()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := databasesql.Open("sqlite", cfg.dsn)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer func() { _ = db.Close() }()
	storage, err := prepareStore(ctx, cfg, db)
	if err != nil {
		return err
	}
	if syncOnly {
		return syncClients(ctx, storage)
	}

	if err := ensureKeys(cfg.keysDir); err != nil {
		return err
	}
	users := &userTable{db: db}
	build := func() ([]op.Option, error) { return buildOptions(cfg, storage, users) }
	opts, err := build()
	if err != nil {
		return err
	}
	handler, err := op.NewReloadable(opts...)
	if err != nil {
		return fmt.Errorf("op.NewReloadable: %w", err)
	}
	go reloadOnHangup(ctx, handler, build)
	go sweepExpiredRows(ctx, storage)

	srv := &http.Server{Addr: cfg.addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	log.Printf("production-sql example listening on %s (issuer %s)", cfg.addr, cfg.issuer)

	select {
	case err := <-errCh:
		return fmt.Errorf("listen: %w", err)
	case <-ctx.Done():
	}
	// Stop accepting first, then let the OP finish queued back-channel
	// logout deliveries.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return errors.Join(srv.Shutdown(shutdownCtx), handler.Shutdown(shutdownCtx))
}

// prepareStore wraps db in the SQL adapter and checks the schema. The
// DSN is never logged: a MySQL or PostgreSQL DSN carries credentials.
func prepareStore(ctx context.Context, cfg config, db *databasesql.DB) (*oidcsql.Store, error) {
	storage, err := oidcsql.New(db, oidcsql.SQLite())
	if err != nil {
		return nil, fmt.Errorf("oidcsql.New: %w", err)
	}
	if !cfg.migrate {
		if err := storage.ValidateSchema(ctx); err != nil {
			return nil, fmt.Errorf("schema check (EXAMPLE53_MIGRATE=1 sets up a development database): %w", err)
		}
		return storage, nil
	}
	if err := storage.Migrate(ctx); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	if err := createDemoUsers(ctx, db); err != nil {
		return nil, fmt.Errorf("create demo users: %w", err)
	}
	log.Printf("development schema and demo users ready")
	return storage, nil
}

// buildOptions is the complete option list. Start-up and every reload
// call it, so a reload re-reads the key directory and nothing else drifts.
// Behind a TLS-terminating ingress, add op.WithTrustedProxies with the
// ingress CIDRs so the OP sees the client address.
func buildOptions(cfg config, storage *oidcsql.Store, users *userTable) ([]op.Option, error) {
	keyset, cookieKeys, err := loadKeys(cfg.keysDir)
	if err != nil {
		return nil, err
	}
	return []op.Option{
		op.WithIssuer(cfg.issuer),
		op.WithStore(storage),
		op.WithKeyset(keyset),
		op.WithCookieKeys(cookieKeys...),
		// The claims behind /userinfo and the ID token come from the same
		// users table the password is checked against.
		op.WithLoginFlow(op.LoginFlow{Primary: op.PrimaryPassword{
			Store:         users,
			LegacySchemes: []op.PasswordHashScheme{op.BcryptHashScheme()},
		}}),
		op.WithStaticClients(staticClients()...),
	}, nil
}

// reloadOnHangup rebuilds the Provider on SIGHUP. A rejected reload
// leaves the running configuration serving.
func reloadOnHangup(ctx context.Context, handler *op.Reloadable, build func() ([]op.Option, error)) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
		}
		opts, err := build()
		if err == nil {
			reloadCtx, cancel := context.WithTimeout(ctx, time.Minute)
			err = handler.Reload(reloadCtx, opts...)
			cancel()
		}
		if err != nil {
			log.Printf("reload rejected, the previous configuration keeps serving: %v", err)
			continue
		}
		log.Printf("reloaded keys and options")
	}
}

// sweepExpiredRows deletes expired OP rows once an hour. Run it on exactly
// one replica (a leader-elected worker or a cron job when there are
// several); it must never be reachable from an HTTP route.
func sweepExpiredRows(ctx context.Context, storage *oidcsql.Store) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			stats, err := storage.GC(ctx, now)
			if err != nil {
				log.Printf("gc failed after deleting %d rows: %v", stats.Total(), err)
				continue
			}
			log.Printf("gc deleted %d expired rows", stats.Total())
		}
	}
}
