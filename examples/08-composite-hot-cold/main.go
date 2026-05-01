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
// op/storeadapter/inmem as a deliberate stand-in so the example boots
// without external dependencies. The live counterpart is
// example 09-redis-volatile, which swaps inmem for the real
// op/storeadapter/redis adapter; every composite.With(...) call below
// stays unchanged.
//
// # Running
//
// Two listeners come up in the same Go process:
//
//   - :8080 — the OP, with issuer http://127.0.0.1:8080, one seeded
//     password user (demo / demo), and one statically-registered
//     public client whose redirect URI points at the RP.
//
//   - :9090 — the RP, built from examples/internal/rpkit. It exposes
//     /, /login, /callback, /me.
//
//     go run -tags example ./examples/08-composite-hot-cold
//     open http://127.0.0.1:9090/
//     # sign in as demo / demo, approve consent
//
// The example creates a fresh SQLite database under the OS temp
// directory so it boots without external dependencies. Production
// embedders point op/storeadapter/sql at MySQL or Postgres (see
// 07-mysql-store) and persist the database where it belongs.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: composite (SQLite durable + inmem volatile); production points op/storeadapter/sql at MySQL or Postgres and swaps the volatile half for op/storeadapter/redis (see 09-redis-volatile).
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - User seed: the demo username / password are hard-coded; production embedders enrol users through their own management plane.
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
	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/composite"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
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
	keys := devkeys.MustEphemeral("composite-1")

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
	// inmem is used here so the example boots without a Redis
	// container. Example 09-redis-volatile shows the same wiring
	// against op/storeadapter/redis; the composite.With(...) calls
	// below stay identical because both backends satisfy
	// store.Store for the substores routed to them.
	volatile := inmem.New()
	log.Printf("volatile store: inmem (see example 09 for the live op/storeadapter/redis variant)")

	// --- Demo user seed (durable backend) ----------------------------
	if err := seedUser(durable); err != nil {
		return fmt.Errorf("seed demo user: %w", err)
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
		op.WithCookieKey(keys.CookieKey),
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
