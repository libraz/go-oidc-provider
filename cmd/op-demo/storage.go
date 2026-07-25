package main

import (
	"context"
	databasesql "database/sql"
	"fmt"
	"log/slog"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/composite"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	oidcredis "github.com/libraz/go-oidc-provider/op/storeadapter/redis"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// Storage backends selectable with -store.
const (
	// storeInmem keeps every record in process memory. It is the default
	// because it needs nothing running alongside the binary, and it is what
	// the automated conformance gate uses.
	storeInmem = "inmem"

	// storeComposite routes the durable substores to MySQL and the volatile
	// ones to Redis, which is the split a deployment actually runs. It
	// exists so a conformance run can be captured against that shape rather
	// than only against the in-memory reference.
	storeComposite = "composite"
)

// storeBackendTimeout bounds the initial connect and schema migration. A
// backend that is not ready by then is a misconfiguration, not a slow start.
const storeBackendTimeout = 60 * time.Second

// demoBackend is everything op-demo needs from whichever storage it was
// pointed at.
//
// users is carried separately because [op.PrimaryPassword] takes a
// [store.UserPasswordStore] and that accessor is not part of the
// [store.Store] interface — the library treats the account table as the
// embedder's, so a store is not required to have one at all.
//
// seed exists for the same reason: writing a user is not on any library
// interface, so each backend supplies its own closure rather than op-demo
// asserting to a concrete type.
type demoBackend struct {
	store store.Store
	users store.UserPasswordStore
	seed  func(ctx context.Context, u *store.User, username string, hash []byte) error
	close func()
}

// openBackend resolves cfg.storeBackend to a live backend.
func openBackend(ctx context.Context, cfg runConfig, logger *slog.Logger) (demoBackend, error) {
	switch cfg.storeBackend {
	case storeInmem, "":
		return openInmemBackend(), nil
	case storeComposite:
		return openCompositeBackend(ctx, cfg, logger)
	default:
		return demoBackend{}, fmt.Errorf(
			"op-demo: unknown -store %q (expected one of: %s, %s)",
			cfg.storeBackend, storeInmem, storeComposite)
	}
}

func openInmemBackend() demoBackend {
	st := inmem.New()
	return demoBackend{
		store: st,
		users: st.UserPasswords(),
		seed: func(ctx context.Context, u *store.User, username string, hash []byte) error {
			st.PutUserWithPassword(ctx, u, username, hash)
			return nil
		},
		close: func() {},
	}
}

// openCompositeBackend connects MySQL and Redis, migrates the schema, and
// routes the substores.
//
// The split mirrors the reference application: everything in the
// transactional cluster stays on MySQL, and only substores whose records are
// short-lived and reconstructible go to Redis. composite.New rejects a
// configuration that would split that cluster across backends, so the
// routing below is checked rather than assumed.
func openCompositeBackend(ctx context.Context, cfg runConfig, logger *slog.Logger) (demoBackend, error) {
	db, err := databasesql.Open("mysql", cfg.mysqlDSN)
	if err != nil {
		return demoBackend{}, fmt.Errorf("open mysql: %w", err)
	}
	closeDB := func() { _ = db.Close() }
	if err := waitForDB(ctx, db, storeBackendTimeout); err != nil {
		closeDB()
		return demoBackend{}, err
	}
	durable, err := oidcsql.New(db, oidcsql.MySQL())
	if err != nil {
		closeDB()
		return demoBackend{}, fmt.Errorf("oidcsql.New: %w", err)
	}
	if err := durable.Migrate(ctx); err != nil {
		closeDB()
		return demoBackend{}, fmt.Errorf("migrate schema: %w", err)
	}

	volatile, err := openRedis(ctx, cfg)
	if err != nil {
		closeDB()
		return demoBackend{}, fmt.Errorf("connect redis: %w", err)
	}
	closeAll := func() {
		_ = volatile.Close()
		closeDB()
	}

	routed, err := composite.New(
		composite.WithDefault(durable),
		composite.With(composite.Sessions, volatile),
		composite.With(composite.Interactions, volatile),
		composite.With(composite.ConsumedJTIs, volatile),
	)
	if err != nil {
		closeAll()
		return demoBackend{}, fmt.Errorf("composite.New: %w", err)
	}
	logger.Info("store backend", "kind", storeComposite, "durable", "mysql", "volatile", "redis")
	return demoBackend{
		store: routed,
		users: durable.UserPasswords(),
		seed: func(ctx context.Context, u *store.User, username string, hash []byte) error {
			return durable.PutUserWithPassword(ctx, u, username, hash)
		},
		close: closeAll,
	}, nil
}

// openRedis dials Redis. Plaintext is admitted explicitly because op-demo is
// a development binary run against a loopback engine; the adapter refuses it
// otherwise, and a deployment uses rediss:// instead.
func openRedis(ctx context.Context, cfg runConfig) (*oidcredis.Store, error) {
	dialCtx, cancel := context.WithTimeout(ctx, storeBackendTimeout)
	defer cancel()
	return oidcredis.New(dialCtx,
		oidcredis.WithDSN(cfg.redisDSN),
		oidcredis.WithRedisAuth(os.Getenv("REDIS_USERNAME"), os.Getenv("REDIS_PASSWORD")),
		oidcredis.WithDevModeAllowPlaintext(func(string) {}),
	)
}

// waitForDB blocks until MySQL answers, so the binary survives being started
// alongside its database rather than strictly after it.
//
// The budget is a context deadline rather than a wall-clock comparison, so a
// caller cancelling during startup stops the retry loop immediately and the
// ping itself inherits the same bound.
func waitForDB(ctx context.Context, db *databasesql.DB, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := db.PingContext(ctx)
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("mysql did not become ready within %s: %w", timeout, err)
		case <-ticker.C:
		}
	}
}
