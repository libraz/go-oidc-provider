//go:build example

// Example 27 shows the production shape of an authentication-factor
// store. The SQL storage adapter (op/storeadapter/sql) persists the
// OIDC core tables, but it does NOT bundle factor stores — TOTP,
// passkey, recovery-code, email-OTP, and lockout persistence are the
// embedder's responsibility. This example fills that gap with a
// hand-written [store.TOTPStore] (see totpstore.go) and, crucially,
// puts its table in the SAME *sql.DB as the core adapter so one
// connection pool and one set of migrations serve both.
//
// TOTP is used as the representative factor. The sqliteTOTPStore in
// totpstore.go is the file you copy for TOTP and adapt for the sibling
// factor stores your login flow requires; the store contracts differ
// only in their columns and their single-use rules.
//
// Run with the example build tag, from this directory so
// ./web/static resolves:
//
//	cd examples/27-durable-mfa-store && go run -tags example .
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP, with the SPA bundle at /login and a SQL-backed
//     store (core tables + the mfa_totp_enrolments factor table).
//   - :9090 — the RP, exposing /, /login, /callback, /me.
//
// Ephemeral vs. durable mode is chosen by the OIDC_EXAMPLE_DB
// environment variable:
//
//   - Unset: the demo uses a throwaway file under the OS temp dir and
//     removes it on every boot, so the TOTP enrolment is re-seeded and
//     the operator banner (otpauth URI + base32 secret) prints each
//     run. This is the "just try it" mode.
//   - Set to a path: the demo persists that file across restarts and
//     never deletes it. The first run seeds and prints the banner;
//     subsequent runs find the existing enrolment, skip re-seeding, and
//     print nothing to re-scan. This proves the factor store is durable.
//
// Operator setup (ephemeral mode):
//
//  1. Start the demo. The startup logs print the otpauth:// URI and a
//     base32 manual-entry secret for the seeded "demo" user.
//  2. Paste the secret (or build a QR from the URI) into your
//     authenticator app. It now produces 6-digit codes for
//     "demo@example.com".
//
// Manual verification:
//
//  1. Open http://127.0.0.1:9090/ — the RP landing page.
//  2. Click "Log in via the OP". The browser is redirected to
//     /authorize and the SPA password screen renders. Sign in as
//     "demo" / "demo".
//  3. The SPA renders the TOTP prompt next; enter the 6-digit code
//     from your authenticator app.
//  4. Approve consent. The browser ends back at /me with the verified
//     ID Token claims as JSON, including "amr": ["mfa","otp","pwd"].
//  5. Durability check: set OIDC_EXAMPLE_DB=/tmp/oidc-mfa.db and start
//     the demo twice. The first boot prints the enrolment banner; the
//     second boot logs "enrolment already present (durable)" and prints
//     no banner — the same scanned secret keeps working across
//     restarts because the factor row survives in SQLite.
//
// Keys stay ephemeral even in durable mode, so a restart still
// invalidates every in-flight session and token; only the persisted
// factor row (and, with OIDC_EXAMPLE_DB set, the core tables) survives.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load signing / cookie / TOTP keys from a vault
//     or KMS so both the core tables and the sealed factor secrets
//     survive process restart.
//   - Factor store: the sql adapter does NOT bundle factor stores;
//     this example's sqliteTOTPStore is the pattern you copy for TOTP
//     and adapt for passkey / recovery / email-OTP / lockout. Run its
//     DDL through your own migration tooling alongside the core schema.
//   - Store: sqlite here for a zero-dependency demo; production uses
//     Postgres / MySQL via op/storeadapter/sql, with the factor table
//     living in the same database.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Demo seed: the enrolment is pre-confirmed at seed time, skipping
//     the round-trip "user types code back" step a production
//     registration screen runs.
package main

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/opkit"
	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
	"github.com/libraz/go-oidc-provider/op/totpkit"
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
	demoEmail    = "demo@example.com"

	totpLabel = "go-oidc-provider demo"

	staticDir = "./web/static"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if _, err := os.Stat(staticDir); err != nil {
		return errors.New("StaticDir " + staticDir + " missing — run from the example directory so ./web/static resolves")
	}

	ctx := context.Background()

	dbPath, durable := resolveDBPath()
	if !durable {
		// Ephemeral mode: throw the file away so every boot re-seeds the
		// enrolment and prints a fresh banner. Durable mode keeps the
		// file so restarts prove the factor row survives.
		_ = os.Remove(dbPath)
	}
	dsn := "file:" + dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := databasesql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer func() { _ = db.Close() }()

	// The core adapter and the factor store share this one *sql.DB, so
	// both persist to the same file and are migrated together. Migrate
	// is a development shortcut; production deployments run
	// storage.Schema() through their own migration tooling instead.
	storage, err := oidcsql.New(db, oidcsql.SQLite())
	if err != nil {
		return fmt.Errorf("oidcsql.New: %w", err)
	}
	if err := storage.Migrate(ctx); err != nil {
		return fmt.Errorf("migrate core: %w", err)
	}

	totpStore := newSQLiteTOTPStore(db)
	if err := totpStore.migrate(ctx); err != nil {
		return fmt.Errorf("migrate factor store: %w", err)
	}
	log.Printf("sqlite store at %s (durable=%t) — core tables + mfa_totp_enrolments", dbPath, durable)

	keys := devkeys.MustEphemeral("durable-mfa-1")

	codec, err := totpkit.NewCodec(keys.TOTPKey)
	if err != nil {
		return fmt.Errorf("totp codec: %w", err)
	}

	if err := seedUser(ctx, storage); err != nil {
		return err
	}
	if err := seedTOTP(ctx, totpStore, codec); err != nil {
		return err
	}

	flow := opkit.WithTOTP(
		opkit.DefaultLoginFlow(storage.Users().(store.UserPasswordStore)),
		totpStore,
		keys.TOTPKey,
	)

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(storage),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithLoginFlow(flow),
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

	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := waitForIssuer(waitCtx, issuer); err != nil {
		return err
	}

	rp, err := rpkit.New(ctx, rpkit.Options{
		Issuer:      issuer,
		ClientID:    clientID,
		RedirectURL: redirectURI,
		Scopes:      []string{"openid", "profile", "email"},
	})
	if err != nil {
		return err
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

// resolveDBPath returns the SQLite file path and whether the demo runs
// in durable mode. When OIDC_EXAMPLE_DB is set the demo persists that
// file across restarts (durable); otherwise it uses a throwaway file
// under the OS temp dir that is wiped on every boot (ephemeral).
func resolveDBPath() (path string, durable bool) {
	if p := os.Getenv("OIDC_EXAMPLE_DB"); p != "" {
		return p, true
	}
	return filepath.Join(os.TempDir(), "oidc-example-27.db"), false
}

// seedUser upserts the demo user and its password hash. The sql
// adapter's PutUserWithPassword is idempotent, so re-running against a
// durable database leaves the existing record intact.
func seedUser(ctx context.Context, storage *oidcsql.Store) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	user := &store.User{
		Subject: demoSubject,
		Claims: map[string]any{
			"name":  "Demo User",
			"email": demoEmail,
		},
		UpdatedAt: time.Now(), //nolint:forbidigo // example boots once at startup; embedders pass their own clock.
	}
	if err := storage.PutUserWithPassword(ctx, user, demoUsername, hash); err != nil {
		return fmt.Errorf("seed user: %w", err)
	}
	return nil
}

// seedTOTP enrols a confirmed TOTP factor for the demo user, but only
// when none exists yet. On a fresh (ephemeral) database it creates the
// record and prints the operator banner; on a durable database that
// already holds the enrolment it prints a short note and leaves the
// previously scanned secret in place.
func seedTOTP(ctx context.Context, totpStore *sqliteTOTPStore, codec *totpkit.Codec) error {
	_, err := totpStore.Get(ctx, demoSubject)
	switch {
	case err == nil:
		log.Println("TOTP enrolment already present (durable) — reuse your previously scanned secret")
		return nil
	case !errors.Is(err, store.ErrNotFound):
		return fmt.Errorf("probe totp enrolment: %w", err)
	}

	pending, err := totpkit.NewEnrolment(codec, demoSubject, totpLabel, demoEmail)
	if err != nil {
		return fmt.Errorf("new totp enrolment: %w", err)
	}
	rec := pending.Record
	rec.ConfirmedAt = time.Now() //nolint:forbidigo // example boots once at startup; embedders pass their own clock.
	if err := totpStore.Put(ctx, rec); err != nil {
		return fmt.Errorf("persist totp enrolment: %w", err)
	}

	log.Println("──────────── TOTP enrolment for demo user ────────────")
	log.Printf("otpauth URI : %s", pending.OTPAuthURI)
	log.Printf("base32 seed : %s", pending.SecretBase32)
	log.Println("enter the base32 secret (or build a QR from the URI) in an authenticator app")
	log.Println("──────────────────────────────────────────────────────")
	return nil
}

// waitForIssuer polls iss + "/.well-known/openid-configuration"
// until it returns 200 or ctx is cancelled. The example boots the
// OP and the RP in the same process, so the RP's OIDC discovery
// runs as soon as the OP listener is ready.
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
