//go:build example

// Command sample is the reference application for go-oidc-provider.
//
// It shows the arc the numbered examples skip: an account coming into
// existence and then being used. A member signs up against the
// application's own table, signs in through the OP, optionally enrols an
// authenticator app, and a relying party completes the round-trip. The
// storage is the shape a deployment actually runs — MySQL for the durable
// substores and the application's own tables, Redis for the volatile ones,
// joined through op/storeadapter/composite.
//
// Three seams the library cares about are visible here rather than
// delegated to a helper:
//
//   - The account table belongs to the application. The OP reaches it only
//     through store.UserPasswordStore (see members.go).
//   - The login and consent UI belongs to the application. It is an
//     interaction.Driver, not the bundled HTML driver (see ui.go).
//   - The application's session is its own, separate from the OP's.
//
// Run the whole stack:
//
//	docker compose -f sample/compose.yaml up -d --build
//	open http://127.0.0.1:8080/
//
// The application is a demonstration and is never meant to be hosted
// publicly: it holds credentials, and nothing about running it as an open
// service adds to what it shows.
package main

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	opstore "github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/composite"
	oidcredis "github.com/libraz/go-oidc-provider/op/storeadapter/redis"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
	"github.com/libraz/go-oidc-provider/op/totpkit"
)

// totpRecord aliases the library's record type so account.go can state the
// narrow store interface it needs without importing the store package.
type totpRecord = opstore.TOTPRecord

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	ctx := context.Background()

	backend, closeBackend, err := openBackend(ctx, cfg)
	if err != nil {
		return err
	}
	defer closeBackend()
	members, totps, storage := backend.members, backend.totps, backend.storage

	// --- Login flow ---------------------------------------------------
	totpCodec, err := totpkit.NewCodec(cfg.MFAKey)
	if err != nil {
		return fmt.Errorf("totp codec: %w", err)
	}
	flow := op.LoginFlow{
		// The password step reads the application's members table
		// through the store interface, not a table the library owns.
		Primary: op.PrimaryPassword{Store: members},
		Rules: []op.Rule{
			// TOTP is demanded only from members who enrolled. StepTOTP
			// fails when no enrolment exists, so an unconditional rule
			// would lock out everyone who never set it up.
			op.RuleWhen(hasTOTPEnrolment(totps, logger), op.StepTOTP{
				Store:         totps,
				EncryptionKey: cfg.MFAKey,
			}),
		},
	}

	driver, err := newAppDriver()
	if err != nil {
		return err
	}

	opts := []op.Option{
		op.WithIssuer(cfg.Issuer),
		op.WithStore(storage),
		op.WithKeyset(cfg.Keyset),
		op.WithCookieKeys(cfg.CookieKey),
		op.WithMFAEncryptionKeys(cfg.MFAKey),
		op.WithLoginFlow(flow),
		op.WithInteractionDriver(driver),
		op.WithStaticClients(op.PublicClient{
			ID:           cfg.ClientID,
			RedirectURIs: []string{cfg.RedirectURI},
			Scopes:       []string{"openid", "profile", "email"},
		}),
	}
	if cfg.Insecure {
		// Loopback demo only. A deployment fronts the OP with TLS and
		// leaves both of these off.
		opts = append(opts, op.WithAllowLocalhostLoopback())
	}

	provider, err := op.New(opts...)
	if err != nil {
		return fmt.Errorf("op.New: %w", err)
	}

	// --- HTTP ---------------------------------------------------------
	ui, err := newAppUI(members, newSessions(), totpEnrolment{
		codec:  totpCodec,
		store:  totps,
		issuer: cfg.Issuer,
	}, time.Now, cfg.RPBase, !cfg.Insecure, logger)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	ui.routes(mux)
	// The OP owns everything the application did not claim. Registering it
	// last on the catch-all pattern means the application's own pages win
	// on exact matches and the OP's protocol routes are reached otherwise.
	mux.Handle("/", provider)

	opErr := make(chan error, 1)
	go func() {
		logger.Info("op listening", "addr", cfg.OPAddr, "issuer", cfg.Issuer)
		opErr <- listen(cfg.OPAddr, mux)
	}()

	if err := waitForIssuer(ctx, cfg.Issuer, cfg.StartupTimeout); err != nil {
		return err
	}

	rp, err := newRelyingParty(ctx, cfg)
	if err != nil {
		return fmt.Errorf("relying party: %w", err)
	}
	rpMux := http.NewServeMux()
	rp.routes(rpMux)

	rpErr := make(chan error, 1)
	go func() {
		logger.Info("relying party listening", "addr", cfg.RPAddr, "url", cfg.RPBase)
		rpErr <- listen(cfg.RPAddr, rpMux)
	}()

	logger.Info("ready", "open", "http://"+cfg.OPAddr+"/")
	select {
	case err := <-opErr:
		return err
	case err := <-rpErr:
		return err
	}
}

// backend bundles the stores the application wires into the provider.
type backend struct {
	members *memberStore
	totps   *mysqlTOTPStore
	storage *composite.Store
}

// openBackend connects both datastores, migrates every schema, and routes
// the substores. It returns a close function rather than leaving the caller
// to unwind two connections in the right order.
//
// The split between the two engines is the point: everything in the
// transactional cluster stays on MySQL, and only substores whose records
// are short-lived and reconstructible go to Redis. composite.New rejects a
// configuration that would split that cluster across backends.
func openBackend(ctx context.Context, cfg config) (backend, func(), error) {
	db, err := databasesql.Open("mysql", cfg.MySQLDSN)
	if err != nil {
		return backend{}, nil, fmt.Errorf("open mysql: %w", err)
	}
	closeDB := func() { _ = db.Close() }
	if err := waitForDB(ctx, db, cfg.StartupTimeout); err != nil {
		closeDB()
		return backend{}, nil, err
	}
	durable, err := oidcsql.New(db, oidcsql.MySQL())
	if err != nil {
		closeDB()
		return backend{}, nil, fmt.Errorf("oidcsql.New: %w", err)
	}
	if err := durable.Migrate(ctx); err != nil {
		closeDB()
		return backend{}, nil, fmt.Errorf("migrate oidc schema: %w", err)
	}

	// The application's tables live in the same database as the OP's, which
	// is what lets signup and the OP's own records commit against one
	// engine. The library never reads them.
	members, err := newMemberStore(ctx, db)
	if err != nil {
		closeDB()
		return backend{}, nil, err
	}
	// The bundled SQL adapter does not persist authentication factors, so
	// the application supplies its own TOTP substore (totpstore.go). That
	// split is the library's design rather than a gap: factor schemas and
	// key management are deployment decisions.
	totps, err := newTOTPStore(ctx, db)
	if err != nil {
		closeDB()
		return backend{}, nil, err
	}

	volatile, err := newRedis(ctx, cfg)
	if err != nil {
		closeDB()
		return backend{}, nil, fmt.Errorf("connect redis: %w", err)
	}
	closeAll := func() {
		_ = volatile.Close()
		closeDB()
	}

	storage, err := composite.New(
		composite.WithDefault(durable),
		composite.With(composite.Sessions, volatile),
		composite.With(composite.Interactions, volatile),
		composite.With(composite.ConsumedJTIs, volatile),
	)
	if err != nil {
		closeAll()
		return backend{}, nil, fmt.Errorf("composite.New: %w", err)
	}
	return backend{members: members, totps: totps, storage: storage}, closeAll, nil
}

// hasTOTPEnrolment reports whether a subject has a confirmed enrolment.
//
// The predicate is synchronous and cannot return an error, so a backend
// fault has to resolve one way or the other. It resolves toward demanding
// the factor: a member who never enrolled then meets a prompt they cannot
// satisfy, which is recoverable, whereas resolving the other way would let
// a member who did enrol past their second factor whenever the store is
// unhealthy.
func hasTOTPEnrolment(totps opstore.TOTPStore, logger *slog.Logger) func(op.LoginContext) bool {
	return func(lc op.LoginContext) bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		switch _, err := totps.Get(ctx, string(lc.Identity.Subject)); {
		case err == nil:
			return true
		case errors.Is(err, opstore.ErrNotFound):
			return false
		default:
			logger.Error("totp enrolment lookup", "err", err)
			return true
		}
	}
}

// listen serves h with timeouts set, so a stalled client cannot hold a
// connection open indefinitely.
func listen(addr string, h http.Handler) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return srv.ListenAndServe()
}

// waitForDB blocks until MySQL answers, so the process survives being
// started alongside its database rather than after it.
func waitForDB(ctx context.Context, db *databasesql.DB, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		if err := db.PingContext(ctx); err == nil {
			return nil
		} else if time.Now().After(deadline) {
			return fmt.Errorf("mysql did not become ready within %s: %w", timeout, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// waitForIssuer blocks until the OP's discovery document is served, so the
// relying party's synchronous discovery call does not race the listener.
func waitForIssuer(ctx context.Context, issuer string, timeout time.Duration) error {
	url := issuer + "/.well-known/openid-configuration"
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: time.Second}
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return err
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("discovery at %s did not become ready within %s", url, timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func newRedis(ctx context.Context, cfg config) (*oidcredis.Store, error) {
	opts := []oidcredis.Option{
		oidcredis.WithDSN(cfg.RedisDSN),
		oidcredis.WithRedisAuth(os.Getenv("REDIS_USERNAME"), os.Getenv("REDIS_PASSWORD")),
	}
	if cfg.Insecure {
		// The adapter refuses plaintext Redis unless the caller says so
		// explicitly. The demo stack keeps Redis on a private compose
		// network; a deployment uses rediss:// and drops this.
		opts = append(opts, oidcredis.WithDevModeAllowPlaintext(func(string) {}))
	}
	dialCtx, cancel := context.WithTimeout(ctx, cfg.StartupTimeout)
	defer cancel()
	return oidcredis.New(dialCtx, opts...)
}

// ensure the driver satisfies the interface at compile time rather than
// at the first render.
var _ interaction.Driver = (*appDriver)(nil)
