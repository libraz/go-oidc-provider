//go:build example

// Example 24-byo-userstore demonstrates how to plug an existing
// "users" table — owned by the embedding application, with column
// names that do not match the OP's bundled schema — into the
// Provider without losing the OIDC-specific record store.
//
// The pattern at a glance:
//
//   - A members table, owned by the embedder, holds member_id,
//     email_address, password_phc, full_name, locale_pref,
//     tenant_id, last_modified. None of those names match the OP's
//     bundled oidc_users schema, and the embedder is free to add
//     more columns the OP never observes.
//   - MemberUserStore projects rows from members onto store.User
//     (Subject / Claims / UpdatedAt) and satisfies
//     store.UserPasswordStore so the PrimaryPassword Step can verify
//     credentials.
//   - All OIDC-specific records (clients, codes, refresh tokens,
//     grants, sessions, PAR, access tokens, IATs, RATs) live in the
//     bundled op/storeadapter/sql schema.
//   - hybridStore embeds *oidcsql.Store and overrides Users() so the
//     OP's /userinfo and ID Token assembly reach MemberUserStore via
//     Go method shadowing. composite is not required for this case
//     because only one substore is being replaced.
//
// Run with the example build tag:
//
//	(cd examples/24-byo-userstore && go run -tags example .)
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP (issuer http://127.0.0.1:8080), with one
//     statically-provisioned public client whose redirect URI points
//     at the RP, and one seeded member (demo@example.test / demo).
//   - :9090 — the RP from examples/internal/rpkit. It exposes /,
//     /login, /callback, /me.
//
// The codebase is split by role across this directory:
//
//   - main.go  — entrypoint, package godoc, listener orchestration,
//     SQLite open + DDL apply, RP wiring through rpkit.
//   - op.go    — OP-side wiring: buildProvider composes oidcsql.Store
//   - MemberUserStore + hybridStore and passes them to op.New.
//   - store.go — embedder-owned types: hybridStore (Users() override)
//     and MemberUserStore (FindBySubject / FindByUsername /
//     ReadPasswordHash) plus the members DDL the run() bootstrap
//     applies.
//   - seed.go  — seedMember helper that upserts the demo row.
//
// Manual verification:
//
//  1. Open http://127.0.0.1:9090/
//  2. Click "Log in via the OP"
//  3. Sign in as demo@example.test / demo
//  4. Approve the consent prompt
//  5. The /me page renders the verified ID Token claims. The "name"
//     and "email" claims are present (released by the profile and
//     email scopes); the "tenant" custom claim — also stored on the
//     members row — is filtered out because no scope authorises it.
//
// The example creates a fresh SQLite database under the OS temp
// directory so it boots without external dependencies. Production
// embedders point op/storeadapter/sql at MySQL or Postgres and run
// the members DDL through their own migration tooling.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: SQLite for OIDC records + a hand-rolled members table; production uses MySQL / Postgres and the embedder's migration tooling.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - User seed: the demo member is hard-coded; production embedders enrol members through their own management plane.
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
	demoSubject  = "mem-0001"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	dbPath := filepath.Join(os.TempDir(), "oidc-example-24.db")
	// Pre-v1 schemas can evolve between checkouts; remove any prior file
	// so a re-run under the new layout never collides with a stale DDL.
	// Production embedders track schema versions through their own
	// migration tooling instead of throwing the database away.
	_ = os.Remove(dbPath)
	dsn := "file:" + dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := databasesql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	if _, err := db.ExecContext(ctx, membersDDL); err != nil {
		return fmt.Errorf("apply members DDL: %w", err)
	}

	if err := seedMember(ctx, db); err != nil {
		return fmt.Errorf("seed demo member: %w", err)
	}

	provider, err := buildProvider(ctx, db)
	if err != nil {
		return err
	}
	log.Printf("OIDC store: sqlite at %s (members + bundled oidc_*)", dbPath)

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
	log.Printf("demo member: username=%q password=%q", demoUsername, demoPassword)

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
