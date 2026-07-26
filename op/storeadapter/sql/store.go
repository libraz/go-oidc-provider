package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// Clock returns the wall-clock time the adapter uses to evaluate
// record expiry. It mirrors the inmem adapter's Clock interface so the
// two backends can be swapped without re-wiring construction.
type Clock interface {
	Now() time.Time
}

type systemClock struct{}

// Now is the wall-clock fallback when no [WithClock] override is
// supplied. The forbidigo allow-list lives here because the adapter is
// a sub-module without access to internal/timex; embedders inject
// internal/timex.Clock through [WithClock].
//
//nolint:forbidigo // sub-module fallback; embedders override via WithClock(clock).
func (systemClock) Now() time.Time { return time.Now() }

// Option configures a [Store] at construction time. Options are
// applied in the order supplied; later calls take precedence.
type Option func(*config)

type config struct {
	clock     Clock
	naming    nameMap
	overrides map[string]string
}

// WithClock injects the wall-clock implementation used to evaluate
// record expiry. The default is the system wall clock.
func WithClock(c Clock) Option {
	return func(cfg *config) {
		if c != nil {
			cfg.clock = c
		}
	}
}

// WithNaming overrides the physical table names. Keys are the logical
// names the adapter uses internally ("clients",
// "authorization_codes", "refresh_tokens", "access_tokens",
// "opaque_access_tokens", "grant_revocations", "revoked_jtis",
// "grants", "sessions", "par_records", "interactions",
// "consumed_jtis", "users", "initial_access_tokens",
// "registration_access_tokens", "op_metadata", "device_codes",
// "ciba_requests"); values are the physical identifiers to use.
// Unknown logical keys cause [New] to return an error so typos surface
// at construction time. Each physical identifier is validated against
// the SQL standard regular identifier grammar before any query is
// built.
func WithNaming(overrides map[string]string) Option {
	return func(cfg *config) {
		if cfg.overrides == nil {
			cfg.overrides = make(map[string]string, len(overrides))
		}
		for k, v := range overrides {
			cfg.overrides[k] = v
		}
	}
}

// Store is the SQL adapter. It satisfies [store.Store],
// [store.ClientRegistry], [store.StaticClientReconciler], and
// [store.Transactional] without any runtime detection: callers can perform a
// direct type assertion when they know they hold a *Store, but the library
// itself works through the interfaces.
type Store struct {
	db      *databasesql.DB
	dialect Dialect
	clock   Clock
	names   nameMap
	queries queries

	clientsImpl            *clientStore
	authCodesImpl          *authCodeStore
	refreshesImpl          *refreshStore
	accessTokensImpl       *accessTokenStore
	opaqueAccessTokensImpl *opaqueAccessTokenStore
	grantRevocationsImpl   *grantRevocationStore
	grantsImpl             *grantStore
	sessionsImpl           *sessionStore
	parsImpl               *parStore
	interactionsImpl       *interactionStore
	jtisImpl               *jtiStore
	usersImpl              *userStore
	iatsImpl               *iatStore
	ratsImpl               *ratStore
	deviceCodesImpl        *deviceCodeStore
	cibaRequestsImpl       *cibaRequestStore
	metadataImpl           *metadataStore
}

// New constructs a Store backed by the supplied *sql.DB. The caller is
// responsible for opening the database with the appropriate driver
// (modernc.org/sqlite, github.com/go-sql-driver/mysql,
// github.com/jackc/pgx/v5/stdlib) and for tuning the connection pool;
// the adapter does not call SetMaxOpenConns or SetMaxIdleConns. New
// fails if db is nil or if any [WithNaming] override is invalid.
func New(db *databasesql.DB, dialect Dialect, opts ...Option) (*Store, error) {
	if db == nil {
		return nil, errors.New("oidcsql: db is nil")
	}
	if dialect.name == "" {
		return nil, errors.New("oidcsql: dialect is the zero value (use SQLite/MySQL/Postgres)")
	}
	cfg := &config{
		clock:  systemClock{},
		naming: defaultNames(),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	if err := cfg.naming.applyOverrides(cfg.overrides); err != nil {
		return nil, err
	}
	q, err := buildQueries(dialect, cfg.naming)
	if err != nil {
		return nil, err
	}
	s := &Store{
		db:      db,
		dialect: dialect,
		clock:   cfg.clock,
		names:   cfg.naming,
		queries: q,
	}
	s.attachSubstores()
	return s, nil
}

// attachSubstores wires the per-substore handles so their query
// templates are built once at construction. Every substore receives a
// reference to the parent Store so it can read the current dialect,
// clock, and table names through a single anchor.
func (s *Store) attachSubstores() {
	s.clientsImpl = newClientStore(s, nil)
	s.authCodesImpl = newAuthCodeStore(s, nil)
	s.refreshesImpl = newRefreshStore(s, nil)
	s.accessTokensImpl = newAccessTokenStore(s, nil)
	s.opaqueAccessTokensImpl = newOpaqueAccessTokenStore(s, nil)
	s.grantRevocationsImpl = newGrantRevocationStore(s, nil)
	s.grantsImpl = newGrantStore(s, nil)
	s.sessionsImpl = newSessionStore(s, nil)
	s.parsImpl = newParStore(s, nil)
	s.interactionsImpl = newInteractionStore(s, nil)
	s.jtisImpl = newJTIStore(s, nil)
	s.usersImpl = newUserStore(s, nil)
	s.iatsImpl = newIATStore(s, nil)
	s.ratsImpl = newRATStore(s, nil)
	s.deviceCodesImpl = newDeviceCodeStore(s)
	s.cibaRequestsImpl = newCIBARequestStore(s)
	s.metadataImpl = newMetadataStore(s, nil)
}

// Schema returns the dialect-specific DDL the adapter expects, with
// any [WithNaming] overrides applied. Embedders typically copy the
// returned string into their migration tooling rather than relying on
// [Store.Migrate]; the schema is exposed verbatim so reviews can
// diff the adapter's expectations against the production schema.
func (s *Store) Schema() string {
	return rewriteSchema(s.dialect.schema, s.names)
}

// Migrate applies the embedded v1 schema to the live connection. It
// is a development convenience for examples and tests; production
// deployments are expected to drive migrations through their existing
// tooling. Migrate splits on ";" so the embedded SQL must use
// statement-terminating semicolons exclusively (which the bundled DDL
// does).
func (s *Store) Migrate(ctx context.Context) error {
	stmts := splitStatements(s.Schema())
	for _, stmt := range stmts {
		if stmt == "" {
			continue
		}
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("oidcsql: applying schema statement %q: %w", trimForError(stmt), err)
		}
	}
	if err := s.validateSchema(ctx); err != nil {
		return err
	}
	return nil
}

var requiredRefreshTokenColumns = []string{ //nolint:gochecknoglobals // schema invariant table; read-only.
	"id",
	"client_id",
	"grant_id",
	"parent_id",
	"subject",
	"subject_public",
	"scope",
	"resource",
	"origin",
	"auth_time",
	"acr",
	"amr",
	"authorization_details",
	"access_token_extra",
	"dpop_jkt",
	"mtls_cert_thumbprint",
	"nonce",
	"revoked",
	"expires_at",
	"consumed_at",
	"created_at",
	"retry_response",
}

func (s *Store) validateSchema(ctx context.Context) error {
	missing, err := s.missingColumns(ctx, s.names.refreshes, requiredRefreshTokenColumns)
	if err != nil {
		return err
	}
	if len(missing) > 0 {
		return fmt.Errorf("oidcsql: schema for %s is missing required columns: %s", s.names.refreshes, strings.Join(missing, ", "))
	}
	return nil
}

func (s *Store) missingColumns(ctx context.Context, table string, required []string) ([]string, error) {
	have, err := s.columnSet(ctx, table)
	if err != nil {
		return nil, err
	}
	missing := make([]string, 0)
	for _, col := range required {
		if !have[col] {
			missing = append(missing, col)
		}
	}
	return missing, nil
}

func (s *Store) columnSet(ctx context.Context, table string) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, s.columnListQuery(), physicalTableName(table))
	if err != nil {
		return nil, fmt.Errorf("oidcsql: inspect columns for %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("oidcsql: scan columns for %s: %w", table, err)
		}
		out[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("oidcsql: iterate columns for %s: %w", table, err)
	}
	return out, nil
}

func (s *Store) columnListQuery() string {
	switch s.dialect.name {
	case "sqlite":
		return "SELECT name FROM pragma_table_info(?)"
	case "mysql":
		return "SELECT column_name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ?"
	case "postgres":
		return "SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1"
	default:
		return ""
	}
}

func physicalTableName(table string) string {
	if i := strings.LastIndex(table, "."); i >= 0 {
		return table[i+1:]
	}
	return table
}

// splitStatements splits raw SQL into individual statements on
// semicolon boundaries that are not inside string literals or line
// comments. The bundled DDL contains line comments that use ";"
// (e.g. "-- VARCHAR(255) is used for opaque identifiers; fits in...")
// and empty string literals, but no block comments. The walker tracks
// the two states it needs and keeps the helper purpose-built rather
// than pulling in a SQL parser.
func splitStatements(src string) []string {
	var (
		out     []string
		cur     strings.Builder
		i, n    = 0, len(src)
		inStr   bool
		comment bool
	)
	cur.Grow(256)
	flush := func() {
		if s := strings.TrimSpace(cur.String()); s != "" {
			out = append(out, s)
		}
		cur.Reset()
	}
	for i < n {
		c := src[i]
		switch {
		case comment:
			// Strip the line comment until newline; preserve the
			// newline so subsequent line numbers in error messages
			// stay aligned.
			if c == '\n' {
				comment = false
				cur.WriteByte(c)
			}
			i++
		case !inStr && c == '-' && i+1 < n && src[i+1] == '-':
			comment = true
			i += 2
		case c == '\'':
			inStr = !inStr
			cur.WriteByte(c)
			i++
		case !inStr && c == ';':
			flush()
			i++
		default:
			cur.WriteByte(c)
			i++
		}
	}
	flush()
	return out
}

func trimForError(stmt string) string {
	const maxLen = 80
	stmt = strings.TrimSpace(stmt)
	if len(stmt) <= maxLen {
		return stmt
	}
	return stmt[:maxLen] + "..."
}

// Close closes the underlying *sql.DB. Embedders that share the *sql.DB
// across components should close it themselves and not call Close on
// the adapter.
func (s *Store) Close() error { return s.db.Close() }

// --- store.Store -------------------------------------------------------------

// Clients returns the read-only [store.ClientStore] handle.
func (s *Store) Clients() store.ClientStore { return s.clientsImpl }

// AuthorizationCodes returns the [store.AuthorizationCodeStore]
// handle.
func (s *Store) AuthorizationCodes() store.AuthorizationCodeStore { return s.authCodesImpl }

// RefreshTokens returns the [store.RefreshTokenStore] handle.
func (s *Store) RefreshTokens() store.RefreshTokenStore { return s.refreshesImpl }

// Grants returns the [store.GrantStore] handle.
func (s *Store) Grants() store.GrantStore { return s.grantsImpl }

// Sessions returns the [store.SessionStore] handle.
func (s *Store) Sessions() store.SessionStore { return s.sessionsImpl }

// PushedAuthRequests returns the [store.PushedAuthRequestStore] handle.
func (s *Store) PushedAuthRequests() store.PushedAuthRequestStore { return s.parsImpl }

// Interactions returns the [store.InteractionStore] handle.
func (s *Store) Interactions() store.InteractionStore { return s.interactionsImpl }

// ConsumedJTIs returns the [store.ConsumedJTIStore] handle.
func (s *Store) ConsumedJTIs() store.ConsumedJTIStore { return s.jtisImpl }

// Users returns the [store.UserStore] handle. The adapter's UserStore
// is read-only; embedders write to oidc_users through their own admin
// plane.
func (s *Store) Users() store.UserStore { return s.usersImpl }

// InitialAccessTokens returns the [store.InitialAccessTokenStore]
// handle. Returns a non-nil handle even if no IAT rows are present;
// the library's nil-check at op.WithDynamicRegistration consults the
// returned interface for nil, which a non-nil *iatStore always
// satisfies.
func (s *Store) InitialAccessTokens() store.InitialAccessTokenStore { return s.iatsImpl }

// RegistrationAccessTokens returns the
// [store.RegistrationAccessTokenStore] handle.
func (s *Store) RegistrationAccessTokens() store.RegistrationAccessTokenStore { return s.ratsImpl }

// AccessTokens returns the [store.AccessTokenRegistry] handle.
func (s *Store) AccessTokens() store.AccessTokenRegistry { return s.accessTokensImpl }

// OpaqueAccessTokens returns the [store.OpaqueAccessTokenStore]
// handle. The handle is non-nil regardless of whether opaque-format
// issuance is enabled; the library's nil-check at op.New consults the
// returned interface for nil, which a non-nil concrete pointer always
// satisfies. Embedders that never enable opaque tokens incur no cost
// beyond the unused table.
func (s *Store) OpaqueAccessTokens() store.OpaqueAccessTokenStore { return s.opaqueAccessTokensImpl }

// GrantRevocations returns the [store.GrantRevocationStore] handle.
// The substore fronts two physical tables (oidc_grant_revocations +
// oidc_revoked_jtis) under one Go type so the verification path's
// denylist-first / tombstone-second precedence rule maps cleanly onto
// two indexable PK lookups. The handle is non-nil regardless of
// whether the embedder selects [op.RevocationStrategyGrantTombstone];
// the library's nil-check at op.New consults the returned interface
// for nil, which a non-nil concrete pointer always satisfies.
func (s *Store) GrantRevocations() store.GrantRevocationStore { return s.grantRevocationsImpl }

// Metadata implements [store.Store] against the oidc_op_metadata
// table. The substore is the persistence path for coarse construction-
// time decisions (subject_mode in v0.9.1; future keys land on the same
// surface without further interface change).
func (s *Store) Metadata() store.MetadataStore { return s.metadataImpl }

// DeviceCodes returns the [store.DeviceCodeStore] handle backing the
// RFC 8628 device-authorization grant. The substore sits outside the
// atomic-routing cluster: its approve→consume compare-and-swap is the
// single-use guarantee, so it is never enlisted in a Tx.
func (s *Store) DeviceCodes() store.DeviceCodeStore { return s.deviceCodesImpl }

// CIBARequests returns the [store.CIBARequestStore] handle backing the
// OpenID Connect CIBA backchannel-authentication grant. The substore
// sits outside the atomic-routing cluster: its approve→consume
// compare-and-swap is the single-use guarantee, so it is never
// enlisted in a Tx.
func (s *Store) CIBARequests() store.CIBARequestStore { return s.cibaRequestsImpl }

// --- store.ClientRegistry ----------------------------------------------------

// Compile-time guard: the library calls cfg.store.(store.ClientRegistry)
// to discover registry support (op.WithStaticClients, dynamic registration
// endpoint). The assertion fails silently at runtime if the receiver loses
// any of the embedded ClientStore methods, so the assignment below pins
// the satisfaction at build time.
var _ store.ClientRegistry = (*Store)(nil)

// GetClient implements [store.ClientStore]. ClientRegistry embeds
// ClientStore, so the *Store receiver MUST expose this method directly
// rather than via the [Clients] accessor for the type assertion in
// op.WithStaticClients to succeed.
func (s *Store) GetClient(ctx context.Context, id string) (*store.Client, error) {
	return s.clientsImpl.GetClient(ctx, id)
}

// RegisterClient persists a fresh client through the dynamic
// registration path. It MUST return [store.ErrAlreadyExists] when the
// ID is already taken.
func (s *Store) RegisterClient(ctx context.Context, c *store.Client) error {
	return s.clientsImpl.Register(ctx, c)
}

// UpdateClient replaces the stored representation of c.ID with c.
func (s *Store) UpdateClient(ctx context.Context, c *store.Client) error {
	return s.clientsImpl.Update(ctx, c)
}

// DeleteClient removes the client identified by id.
func (s *Store) DeleteClient(ctx context.Context, id string) error {
	return s.clientsImpl.Delete(ctx, id)
}

// runner abstracts *sql.DB and *sql.Tx so substores can use the same
// query path inside and outside a transaction. It is intentionally
// the smallest possible surface: ExecContext and QueryContext.
type runner interface {
	ExecContext(ctx context.Context, query string, args ...any) (databasesql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*databasesql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *databasesql.Row
}
