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
// "authorization_codes", "refresh_tokens", "access_tokens", "grants",
// "sessions", "par_records", "interactions", "consumed_jtis", "users",
// "initial_access_tokens", "registration_access_tokens"); values are
// the physical identifiers to use. Unknown logical keys cause [New]
// to return an error so typos surface at construction time. Each
// physical identifier is validated against the SQL standard regular
// identifier grammar before any query is built.
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
// [store.ClientRegistry], and [store.Transactional] without any
// runtime detection: callers can perform a direct type assertion when
// they know they hold a *Store, but the library itself works through
// the interfaces.
type Store struct {
	db      *databasesql.DB
	dialect Dialect
	clock   Clock
	names   nameMap
	queries queries

	clientsImpl      *clientStore
	authCodesImpl    *authCodeStore
	refreshesImpl    *refreshStore
	accessTokensImpl *accessTokenStore
	grantsImpl       *grantStore
	sessionsImpl     *sessionStore
	parsImpl         *parStore
	interactionsImpl *interactionStore
	jtisImpl         *jtiStore
	usersImpl        *userStore
	iatsImpl         *iatStore
	ratsImpl         *ratStore
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
	s.grantsImpl = newGrantStore(s, nil)
	s.sessionsImpl = newSessionStore(s, nil)
	s.parsImpl = newParStore(s, nil)
	s.interactionsImpl = newInteractionStore(s, nil)
	s.jtisImpl = newJTIStore(s, nil)
	s.usersImpl = newUserStore(s, nil)
	s.iatsImpl = newIATStore(s, nil)
	s.ratsImpl = newRATStore(s, nil)
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
	return nil
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

// --- store.ClientRegistry ----------------------------------------------------

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
