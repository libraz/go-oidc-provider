//go:build example

// Example 08-composite-hot-cold demonstrates the canonical hot/cold
// storage split: durable records (clients, authorization codes,
// refresh tokens, grants, sessions, PAR, access tokens, users, IATs,
// RATs) live in a SQL backend, while volatile records (interactions,
// consumed JTIs) live in a fast non-durable store.
//
// The composite adapter enforces a critical invariant at construction
// time: every substore that participates in atomic commits
// (composite.TxClusterKinds — AuthorizationCodes, RefreshTokens,
// Grants, Sessions, PushedAuthRequests, AccessTokens) MUST resolve to
// the same backend. Splitting them across backends would shatter the
// "code → token + grant" rotation atomicity and open a replay
// window. composite.New rejects misconfigured wiring with
// composite.ErrTxClusterSplit before the OP starts serving.
//
// # Where Redis goes
//
// The non-cluster volatile substores (Interactions, ConsumedJTIs) are
// the right fit for a fast key/value store. This example uses
// op/storeadapter/inmem as a stand-in until op/storeadapter/redis (K2
// in 007 §3.2) lands. To swap inmem for Redis later, replace the
// `volatile := inmem.New()` line with the Redis adapter constructor;
// every composite.With(...) call below stays unchanged.
//
// Run with:
//
//	go run -tags example ./examples/08-composite-hot-cold
//
// The example creates a fresh SQLite database under the OS temp
// directory so it boots without external dependencies. Production
// embedders point op/storeadapter/sql at MySQL or Postgres (see
// 07-mysql-store) and persist the database where it belongs.
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
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/composite"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
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

	// --- Durable backend: SQL adapter against SQLite -----------------
	// Production embedders swap SQLite for MySQL or Postgres here; the
	// composite.With(...) calls below do not depend on the engine.
	dbPath := filepath.Join(os.TempDir(), "oidc-example-08.db")
	dsn := "file:" + dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := databasesql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer func() { _ = db.Close() }()

	durable, err := oidcsql.New(db, oidcsql.SQLite())
	if err != nil {
		return fmt.Errorf("oidcsql.New: %w", err)
	}
	if err := durable.Migrate(context.Background()); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	log.Printf("durable store: sqlite at %s", dbPath)

	// --- Volatile backend: stand-in for Redis ------------------------
	// When op/storeadapter/redis lands (K2 in 007 §3.2), swap this
	// single line for the Redis adapter constructor. The composite
	// wiring below stays identical because both backends satisfy the
	// same store.Store interface.
	volatile := inmem.New()
	log.Printf("volatile store: inmem (replace with Redis adapter when K2 ships)")

	// --- Static client seeding ---------------------------------------
	// composite.Store deliberately does NOT implement
	// store.ClientRegistry directly (see the godoc on
	// composite.Store.ClientRegistry — exposing the interface would
	// hide the case where the routed Clients backend is read-only).
	// op.WithStaticClients does a type assertion against the supplied
	// store, so seeding is done here against the SQL adapter
	// directly, before the composite wraps it. The same pattern
	// applies to dynamic registration; embedders that need both
	// composite and DCR seed clients through the SQL adapter and
	// surface the registry to op via a small wrapper they own.
	seed := &store.Client{
		ID:           "demo-spa",
		RedirectURIs: []string{"https://rp.example.com/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       []string{"openid", "profile", "email"},
	}
	if err := durable.RegisterClient(context.Background(), seed); err != nil {
		// The sqlite database under /tmp persists across runs, so the
		// second invocation finds demo-spa already present. Treat that
		// as a no-op rather than a hard error.
		if !errors.Is(err, store.ErrAlreadyExists) {
			return fmt.Errorf("seed demo-spa: %w", err)
		}
	}

	// --- Composite wiring --------------------------------------------
	// Every Kind in composite.TxClusterKinds resolves to `durable` via
	// WithDefault. Two volatile Kinds (Interactions, ConsumedJTIs)
	// override to `volatile` via With(). Composite.New validates that
	// the cluster is not split before returning.
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
		op.WithKeyset(op.Keyset{{KeyID: "composite-1", Signer: priv}}),
		op.WithCookieKey(cookieKey),
	)
	if err != nil {
		return fmt.Errorf("op.New: %w", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("OP backed by composite (sqlite + inmem) listening on :8080 (issuer https://op.example.com)")
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
