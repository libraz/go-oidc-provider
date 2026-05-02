//go:build example

// Example 18-byo-userstore demonstrates how to plug an existing
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
//	go run -tags example ./examples/18-byo-userstore
//
// Two listeners come up in the same process:
//
//   - :8080 — the OP (issuer http://127.0.0.1:8080), with one
//     statically-provisioned public client whose redirect URI points
//     at the RP, and one seeded member (demo@example.test / demo).
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

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
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

// membersDDL is the embedder-owned schema. Column names deliberately
// avoid the OP's bundled oidc_users layout (subject / claims /
// updated_at / username / password_hash) to make it concrete that
// MemberUserStore is doing the projection: nothing in the OP cares
// about these column names.
const membersDDL = `
CREATE TABLE IF NOT EXISTS members (
    member_id      TEXT PRIMARY KEY,
    email_address  TEXT NOT NULL,
    password_phc   BLOB NOT NULL,
    full_name      TEXT,
    locale_pref    TEXT,
    tenant_id      TEXT,
    last_modified  INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS members_email ON members (email_address);
`

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	keys := devkeys.MustEphemeral("byo-userstore-1")

	dbPath := filepath.Join(os.TempDir(), "oidc-example-18.db")
	dsn := "file:" + dbPath + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := databasesql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open sqlite: %w", err)
	}
	defer func() { _ = db.Close() }()

	if _, err := db.ExecContext(context.Background(), membersDDL); err != nil {
		return fmt.Errorf("apply members DDL: %w", err)
	}

	durable, err := oidcsql.New(db, oidcsql.SQLite())
	if err != nil {
		return fmt.Errorf("oidcsql.New: %w", err)
	}
	if err := durable.Migrate(context.Background()); err != nil {
		return fmt.Errorf("migrate OIDC schema: %w", err)
	}
	log.Printf("OIDC store: sqlite at %s (members + bundled oidc_*)", dbPath)

	members := &MemberUserStore{db: db}

	if err := seedMember(context.Background(), db); err != nil {
		return fmt.Errorf("seed demo member: %w", err)
	}

	// hybridStore is the value op.WithStore receives. The embedded
	// *oidcsql.Store provides every store.Store method except
	// Users(): that one is shadowed by the wrapper's own method, so
	// the OP's /userinfo and ID Token assembly reach MemberUserStore
	// at every call site that reads end-user claims.
	storage := &hybridStore{Store: durable, users: members}

	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: members},
	}

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

// hybridStore wraps an oidcsql.Store and replaces only the Users()
// substore with an embedder-supplied implementation. Every other
// substore method (Clients, AuthorizationCodes, RefreshTokens,
// Grants, Sessions, PushedAuthRequests, Interactions, ConsumedJTIs,
// InitialAccessTokens, RegistrationAccessTokens, AccessTokens,
// OpaqueAccessTokens, GrantRevocations) is provided by the embedded
// *oidcsql.Store via Go method promotion.
//
// The store.Transactional capability is also inherited from the
// embedded oidcsql.Store, so the transactional cluster
// (authorization-code exchange, refresh-token rotation, PAR
// consumption) commits atomically against the same SQLite database.
// Users is intentionally outside the cluster (store.Tx has no
// Users() accessor), so routing it to a different backend cannot
// break atomicity.
type hybridStore struct {
	*oidcsql.Store
	users store.UserPasswordStore
}

// Users overrides oidcsql.Store.Users() so the OP reads end-user
// records from the embedder-owned members table.
func (h *hybridStore) Users() store.UserStore { return h.users }

// MemberUserStore projects the members table onto store.User and
// satisfies store.UserPasswordStore. The struct holds only the
// *sql.DB; SQL templates live as string constants below so the
// example is single-file readable. Production embedders would lift
// them into a query builder of their choice.
type MemberUserStore struct {
	db *databasesql.DB
}

const (
	memberSelectBySubject   = `SELECT member_id, email_address, full_name, locale_pref, tenant_id, last_modified FROM members WHERE member_id = ?`
	memberSelectByEmail     = `SELECT member_id, email_address, full_name, locale_pref, tenant_id, last_modified FROM members WHERE email_address = ?`
	memberSelectPasswordPHC = `SELECT password_phc FROM members WHERE member_id = ?`
)

// FindBySubject implements store.UserStore.FindBySubject.
func (m *MemberUserStore) FindBySubject(ctx context.Context, sub string) (*store.User, error) {
	return m.scanMember(ctx, memberSelectBySubject, sub)
}

// FindByUsername implements store.UserPasswordStore.FindByUsername.
// The embedder treats "username" as "email_address" — the column the
// PrimaryPassword Step's input string is matched against. Production
// embedders MAY case-fold the value here as long as FindBySubject is
// consistent so the resolved subject is stable across login paths.
func (m *MemberUserStore) FindByUsername(ctx context.Context, username string) (*store.User, error) {
	return m.scanMember(ctx, memberSelectByEmail, username)
}

// ReadPasswordHash implements store.UserPasswordStore.ReadPasswordHash.
// It returns store.ErrNotFound both when the subject is unknown and
// when the row exists but carries no password (e.g. an
// invitation-only member that has not yet enrolled), so the
// orchestrator surfaces an enumeration-safe response.
func (m *MemberUserStore) ReadPasswordHash(ctx context.Context, subject string) ([]byte, error) {
	var hash []byte
	err := m.db.QueryRowContext(ctx, memberSelectPasswordPHC, subject).Scan(&hash)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("members.ReadPasswordHash: %w", err)
	}
	if len(hash) == 0 {
		return nil, store.ErrNotFound
	}
	out := make([]byte, len(hash))
	copy(out, hash)
	return out, nil
}

// scanMember projects a SELECT row onto store.User. Columns the OP
// does not consume (tenant_id is the example) are still loaded and
// placed on Claims so embedders can demonstrate scope-based
// filtering: the OP releases only the claim names authorised by the
// granted scopes, so tenant remains invisible to the RP unless the
// embedder adds a scope that releases it.
func (m *MemberUserStore) scanMember(ctx context.Context, query, arg string) (*store.User, error) {
	var (
		subject    string
		email      databasesql.NullString
		fullName   databasesql.NullString
		localePref databasesql.NullString
		tenantID   databasesql.NullString
		updatedAt  int64
	)
	err := m.db.QueryRowContext(ctx, query, arg).
		Scan(&subject, &email, &fullName, &localePref, &tenantID, &updatedAt)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("members.scan: %w", err)
	}

	claims := map[string]any{}
	if email.Valid {
		claims["email"] = email.String
	}
	if fullName.Valid {
		claims["name"] = fullName.String
	}
	if localePref.Valid {
		claims["locale"] = localePref.String
	}
	if tenantID.Valid {
		// Custom embedder claim. Not authorised by any standard
		// scope, so the OP filters it out of /userinfo and ID Token
		// responses. Embedders that want to release it MUST register
		// a custom scope or use the OIDC Core §5.5 claims parameter.
		claims["tenant"] = tenantID.String
	}

	return &store.User{
		Subject:   subject,
		Claims:    claims,
		UpdatedAt: time.Unix(updatedAt, 0),
	}, nil
}

func seedMember(ctx context.Context, db *databasesql.DB) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	const upsert = `
INSERT INTO members (member_id, email_address, password_phc, full_name, locale_pref, tenant_id, last_modified)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(member_id) DO UPDATE SET
    email_address = excluded.email_address,
    password_phc  = excluded.password_phc,
    full_name     = excluded.full_name,
    locale_pref   = excluded.locale_pref,
    tenant_id     = excluded.tenant_id,
    last_modified = excluded.last_modified;
`
	now := time.Now().Unix() //nolint:forbidigo // example seed script — not OP business logic; internal/timex is unreachable from examples/.
	_, err = db.ExecContext(ctx, upsert,
		demoSubject, demoUsername, hash,
		"Demo Member", "en-US", "tenant-acme", now,
	)
	if err != nil {
		return fmt.Errorf("seed member: %w", err)
	}
	return nil
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
