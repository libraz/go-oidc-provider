//go:build example

// Example 26-byo-store-from-scratch implements the whole store.Store
// aggregate by hand, against a SQLite database whose table AND column
// names look nothing like the OP's bundled schema. It answers the
// question "can I use any table name and any column name for every
// table backing the OP?" with a runnable proof: yes, when you supply
// your own store.Store the library observes none of the physical
// names — it only sees the store.* Go structs your code maps rows
// onto.
//
// The bundled op/storeadapter/sql adapter already lets you rename
// tables (WithNaming) but pins the column names. To rename columns
// too you implement the substore interfaces yourself, which is what
// this example does end to end.
//
// # What is implemented
//
// scratchStore (store.go) satisfies store.Store and store.Transactional.
// Every substore the authorization-code browser flow and op.New
// construction touch is implemented non-nil:
//
//   - Clients (GetClient only — no dynamic registration)
//   - AuthorizationCodes, RefreshTokens, Grants, PushedAuthRequests
//     (the transactional cluster; substores bind to either *sql.DB or
//     *sql.Tx through a small querier interface, exactly like the
//     bundled adapter)
//   - Sessions, Interactions, ConsumedJTIs
//   - Users (store.UserPasswordStore: FindBySubject / FindByUsername /
//     ReadPasswordHash)
//   - AccessTokens (store.AccessTokenRegistry)
//   - Metadata (store.MetadataStore — so op.New does not emit the
//     pairwise-immutability startup warning)
//
// Substores the demo does not exercise return nil and the matching
// option is pinned so the library never requires them:
// OpaqueAccessTokens, InitialAccessTokens, RegistrationAccessTokens,
// DeviceCodes, CIBARequests, and GrantRevocations (paired with
// op.WithAccessTokenRevocationStrategy(op.RevocationStrategyNone)).
//
// # Hash-on-store
//
// AuthorizationCode.ID, RefreshToken.ID, and PushedAuthRequest.URI are
// opaque bearer secrets. Following op/store/doc.go §Hash-on-store, the
// store hashes the presented value (SHA-256, no pepper — matching the
// inmem reference) before persisting, stores only the digest, and on
// Find/Consume hashes the presented value to look the digest up,
// comparing in constant time. A database leak therefore yields one-way
// digests that cannot be redeemed.
//
// # Custom naming convention
//
// Every table is prefixed "vault_" and every column uses a
// deliberately non-OIDC vocabulary (principal instead of subject,
// relying_party instead of client_id, ledger / token_secret_digest /
// issued_epoch / expires_epoch / consumed_epoch, ...). See schema.go
// for the full DDL. The OP observes none of these names; the substore
// implementations are the sole place the physical schema is mapped
// onto the store.* structs.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/26-byo-store-from-scratch
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP (issuer http://127.0.0.1:8080), with one
//     statically-provisioned public client whose redirect URI points
//     at the RP, and one seeded user (demo@example.test / demo).
//   - :9090 — the RP from examples/internal/rpkit. It exposes /,
//     /login, /callback, /me.
//
// Manual verification:
//
//  1. Open http://127.0.0.1:9090/
//  2. Click "Log in via the OP"
//  3. Sign in as demo@example.test / demo
//  4. Approve the consent prompt
//  5. The /me page renders the verified ID Token claims. The "name"
//     and "email" claims are present (released by the profile and
//     email scopes).
//
// The example creates a fresh SQLite database under the OS temp
// directory so it boots without external dependencies.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: SQLite + a hand-rolled schema; production embedders point
//     this pattern at their real database and migration tooling.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - User seed: the demo user is hard-coded; production embedders
//     enrol users through their own management plane.
//   - Digest: SHA-256 without a pepper (matching the inmem reference).
//     A production backend SHOULD HMAC the digest with a server-side
//     pepper so a database leak alone cannot confirm a guessed token.
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

	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
)

const (
	opAddr      = ":8080"
	rpAddr      = ":9090"
	issuer      = "http://127.0.0.1" + opAddr
	rpBase      = "http://127.0.0.1" + rpAddr
	clientID    = "demo-rp"
	redirectURI = rpBase + "/callback"

	demoUsername = "demo@example.test"
	demoPassword = "demo"
	demoSubject  = "principal-0001"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	dbPath := filepath.Join(os.TempDir(), "oidc-example-26.db")
	// Pre-v1 schemas can evolve between checkouts; remove any prior file
	// so a re-run never collides with a stale DDL. Production embedders
	// track schema versions through their own migration tooling instead
	// of throwing the database away.
	_ = os.Remove(dbPath)
	dsn := "file:" + dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := databasesql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	storage := newScratchStore(db)
	if err := storage.Migrate(ctx); err != nil {
		return fmt.Errorf("apply scratch schema: %w", err)
	}

	if err := seedUser(ctx, db); err != nil {
		return fmt.Errorf("seed demo user: %w", err)
	}
	if err := seedClient(ctx, db); err != nil {
		return fmt.Errorf("seed demo client: %w", err)
	}

	provider, err := buildProvider(storage)
	if err != nil {
		return err
	}
	log.Printf("OIDC store: sqlite at %s (hand-rolled vault_* schema)", dbPath)

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
