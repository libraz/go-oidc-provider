package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"slices"
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
	prefix    string
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

// WithTablePrefix sets the prefix every default table name carries. The
// default is "oidc_", producing names like "oidc_authorization_codes"; the
// empty prefix produces "authorization_codes". A deployment that shares a
// database with its application, or runs several OPs in one schema, gives
// each its own prefix; an empty or generic prefix there collides with the
// application's own tables (users, sessions, clients). The prefix reaches
// the queries, [Store.Schema], [Store.Migrations], [Store.Migrate], the
// schema checks and [Store.GC] alike, and the DDL's index names follow the
// table names. [WithNaming]
// entries still override individual tables outright, prefix or not.
//
// The prefix also names the version table [Store.Migrate] records in,
// "<prefix>schema_migrations". Migrate refuses the empty prefix, under which
// that table would be "schema_migrations", golang-migrate's default and so
// usually the application's own history; apply [Store.Migrations] with a
// migration tool instead.
//
// The prefix is validated like a [WithNaming] value (ASCII letters, digits
// and underscore, not starting with a digit, each resulting name within 63
// bytes); [New] returns an error otherwise.
//
// Stable since v1.5.
func WithTablePrefix(prefix string) Option {
	return func(cfg *config) { cfg.prefix = prefix }
}

// WithNaming overrides the physical table names. Keys are the logical
// names the adapter uses internally ("clients",
// "authorization_codes", "refresh_tokens", "access_tokens",
// "opaque_access_tokens", "grant_revocations", "revoked_jtis",
// "grants", "sessions", "par_records", "interactions",
// "consumed_jtis", "users", "initial_access_tokens",
// "registration_access_tokens", "op_metadata", "device_codes",
// "ciba_requests", "totp_secrets", "passkeys", "recovery_codes",
// "email_otps", "authn_lockouts", "ssf_streams", "ssf_events"); values
// are the physical identifiers to use.
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
// [store.ClientRegistry], [store.StaticClientReconciler],
// [store.SharedSignalsStore], and [store.Transactional] without any runtime detection: callers can perform a
// direct type assertion when they know they hold a *Store, but the library
// itself works through the interfaces.
type Store struct {
	db      *databasesql.DB
	dialect Dialect
	clock   Clock
	prefix  string
	names   nameMap
	queries queries

	// txGate admits one transaction at a time on engines that need
	// them serialised, and is nil on the engines that do not. See
	// [Dialect.serializesTransactions].
	txGate chan struct{}

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

	totpsImpl         *totpStore
	passkeysImpl      *passkeyStore
	recoveryCodesImpl *recoveryStore
	emailOTPsImpl     *emailOTPStore
	authnLockoutsImpl *authnLockoutStore

	ssfStreamsImpl *ssfStreamStore
	ssfEventsImpl  *ssfEventStore
}

// New constructs a Store backed by the supplied *sql.DB. The caller is
// responsible for opening the database with the appropriate driver
// (modernc.org/sqlite, github.com/go-sql-driver/mysql,
// github.com/jackc/pgx/v5/stdlib) and for tuning the connection pool;
// the adapter does not call SetMaxOpenConns or SetMaxIdleConns, and it
// never closes db, which stays the caller's to close. New
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
		prefix: defaultTablePrefix,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}
	if err := validateTablePrefix(cfg.prefix); err != nil {
		return nil, err
	}
	cfg.naming = namesWithPrefix(cfg.prefix)
	if err := cfg.naming.applyOverrides(cfg.overrides); err != nil {
		return nil, err
	}
	if err := cfg.naming.validateIndexNames(dialect); err != nil {
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
		prefix:  cfg.prefix,
		names:   cfg.naming,
		queries: q,
	}
	if dialect.serializesTransactions() {
		s.txGate = make(chan struct{}, 1)
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
	s.totpsImpl = newTOTPStore(s)
	s.passkeysImpl = newPasskeyStore(s)
	s.recoveryCodesImpl = newRecoveryStore(s)
	s.emailOTPsImpl = newEmailOTPStore(s)
	s.authnLockoutsImpl = newAuthnLockoutStore(s)
	s.ssfStreamsImpl = &ssfStreamStore{parent: s}
	s.ssfEventsImpl = &ssfEventStore{parent: s}
}

// The authentication-factor substores are deliberately absent from
// [store.Store]: the login flow receives them directly, and a
// deployment that never enables a second factor should not have to
// provision their tables. Each accessor mirrors the name the inmem
// reference adapter uses so the two are drop-in interchangeable.

// TOTPs returns the [store.TOTPStore] backed by the totp_secrets table.
// Wire it into a login flow through op.StepTOTP.
func (s *Store) TOTPs() store.TOTPStore { return s.totpsImpl }

// Passkeys returns the [store.PasskeyStore] backed by the passkeys
// table. Wire it into a login flow through op.PrimaryPasskey or
// op.StepPasskey.
func (s *Store) Passkeys() store.PasskeyStore { return s.passkeysImpl }

// RecoveryCodes returns the [store.RecoveryStore] backed by the
// recovery_codes table.
func (s *Store) RecoveryCodes() store.RecoveryStore { return s.recoveryCodesImpl }

// EmailOTPs returns the [store.EmailOTPStore] backed by the email_otps
// table.
func (s *Store) EmailOTPs() store.EmailOTPStore { return s.emailOTPsImpl }

// AuthnLockouts returns the [store.AuthnLockoutStore] backed by the
// authn_lockouts table. Wire it through op.WithAuthnLockoutStore to
// give the cross-factor brute-force counter a durable home.
func (s *Store) AuthnLockouts() store.AuthnLockoutStore { return s.authnLockoutsImpl }

// Schema returns the dialect-specific DDL of this release's complete schema,
// with [WithTablePrefix] and [WithNaming] applied. It is a reference: diff it
// against a production schema in review, or read from it the tables, columns
// and indexes [Store.ValidateSchema] requires. Databases are created and
// upgraded from the files of [Store.Migrations], through [Store.Migrate] or a
// migration tool.
func (s *Store) Schema() string {
	return rewriteSchema(s.dialect.schema, s.names)
}

// Migrate brings the database to this release's schema: it applies, in order,
// the files of [Store.Migrations] the database has not applied yet and records
// each in the version table "<prefix>schema_migrations" (by default
// "oidc_schema_migrations"). The table has golang-migrate's layout and holds
// the number of the last file applied, so golang-migrate pointed at it with
// x-migrations-table continues from the same version, and so does Migrate
// after golang-migrate. Migrate is meant for production: call it once from a
// deploy job, before the new release serves, with a ctx sized for the DDL (a
// MySQL release that rebuilds tables takes as long as the tables are large).
// It never needs multiStatements=true in a MySQL DSN.
//
// Concurrent calls wait for each other: on MySQL and PostgreSQL through the
// advisory lock golang-migrate takes for the same version table, on SQLite
// through BEGIN IMMEDIATE. On PostgreSQL the version table and the lock follow
// current_schema(), so keep the adapter's tables in the first schema of the
// search_path, and connect directly or through session pooling, since a
// transaction pooler does not hold a session lock.
//
// On PostgreSQL and SQLite a file commits together with its version record.
// MySQL commits DDL implicitly, so Migrate marks the version dirty before a
// file and clean after it; a file that fails part-way leaves it dirty, and
// Migrate refuses a dirty version until it is corrected by hand, with the
// statement its error shows.
//
// A database with the adapter's tables but no version table is recorded at
// this release when [Store.ValidateSchema] passes on it; otherwise Migrate
// refuses having changed nothing, and its error names the version to record
// or the migrations to apply first. Before any DDL, Migrate also refuses when
// a table on one of the adapter's names lacks a column of the first release,
// so it never alters another application's table. A version newer than this
// release applies nothing. Migrate ends with [Store.ValidateSchema] on the
// result and returns its error.
//
// Migrate refuses an empty [WithTablePrefix]: the version table would then be
// golang-migrate's default "schema_migrations".
//
// Signature stable since v0.9; the behaviour above since v1.5.
func (s *Store) Migrate(ctx context.Context) error {
	return s.migrate(ctx)
}

// ValidateSchema checks every table the adapter owns, whether or not the
// configuration uses it: each table must exist and carry every column the
// reference DDL declares (columns an embedder added are allowed; types are not
// checked), and on MySQL
// the identifier columns must use a binary collation. Every column the
// reference DDL leads an index with must lead some index of the table, under
// any index name; an index an embedder added is allowed. It reads the catalog
// only: it never creates, alters or drops anything, so the connecting role
// needs no CREATE privilege.
//
// op.New already checks, at construction, the tables the configuration
// uses, through each substore's own ValidateSchema. Call this full check
// from CI or a deploy gate, where a table a later configuration change
// would need should fail before the change ships.
//
// A missing table is reported as "oidcsql: schema for <table> is missing";
// a missing column as "oidcsql: schema for <table> is missing required
// columns: <names>", followed, for a column a later release added, by the
// migration under schema/migrations/<dialect> that adds it. When any table is
// missing, one closing line says how to create it. Every gap is reported in the
// one returned error, a line each, so a single run lists the whole
// migration still to apply. A missing index is reported as "oidcsql: <table>
// has no index on <columns>". When every gap is something a later release
// added, a closing line gives the "migrate force" number for a database
// golang-migrate does not track yet. [Store.Migrate] runs this check after
// applying the migrations.
//
// Stable since v1.5.
func (s *Store) ValidateSchema(ctx context.Context) error {
	return s.validateKeys(ctx, knownNamingKeys...)
}

// checkColumns reports the required columns an existing table lacks, and
// records the release that added each in gap.
func (s *Store) checkColumns(key, table string, cols map[string]bool, required []string, gap *releaseGap) error {
	var missing []string
	for _, col := range required {
		if !cols[col] {
			missing = append(missing, col)
			gap.add(columnAddedIn(key, col))
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf("oidcsql: schema for %s is missing required columns: %s%s",
		table, strings.Join(missing, ", "), migrationHint(s.dialect.name, key, missing))
}

// validateKeys runs the [Store.ValidateSchema] checks on the tables with
// the given WithNaming keys only.
func (s *Store) validateKeys(ctx context.Context, keys ...string) error {
	return s.validateKeysOn(ctx, dbRunner{db: s.db}, keys...)
}

// validateKeysOn is [Store.validateKeys] reading the catalog through r.
func (s *Store) validateKeysOn(ctx context.Context, r runner, keys ...string) error {
	report, err := s.inspectSchema(ctx, r, keys...)
	if err != nil {
		return err
	}
	return report.err()
}

// schemaReport is what the schema checks found on a set of tables.
type schemaReport struct {
	problems   []error
	gap        releaseGap
	tableFound bool
	// indexOrCollation is set when an existing table lacks an index or has a
	// non-binary collation, problems [releaseGap] does not date.
	indexOrCollation bool
}

// err joins the problems into the error [Store.ValidateSchema] returns, nil
// when there are none.
func (r schemaReport) err() error {
	return errors.Join(r.problems...)
}

// inspectSchema runs the [Store.ValidateSchema] checks on the tables with the
// given WithNaming keys, reading the catalog through r.
func (s *Store) inspectSchema(ctx context.Context, r runner, keys ...string) (schemaReport, error) {
	required := ddlColumns(s.dialect)
	var report schemaReport
	var tableMissing bool
	var scope string
	for _, key := range keys {
		table := s.names.byKey(key)
		cols, err := s.columnSetOn(ctx, r, table)
		if err != nil {
			return schemaReport{}, err
		}
		if len(cols) == 0 {
			if !tableMissing {
				scope = s.lookupScope(ctx, r)
			}
			tableMissing = true
			report.gap.add(tableAddedIn(key))
			report.problems = append(report.problems, missingTableError(table, scope, tableMigrationHint(s.dialect.name, key)))
			continue
		}
		report.tableFound = true
		if err := s.checkExistingTable(ctx, r, key, table, cols, required[key], &report); err != nil {
			return schemaReport{}, err
		}
	}
	if tableMissing {
		report.problems = append(report.problems, errors.New(s.missingTableRemedy()))
	}
	if hint := report.gap.hint(); report.tableFound && hint != nil {
		report.problems = append(report.problems, hint)
	}
	return report, nil
}

// checkExistingTable runs the column, collation and index checks on a table
// that exists and adds what they find to report.
func (s *Store) checkExistingTable(ctx context.Context, r runner, key, table string, cols map[string]bool, required []string, report *schemaReport) error {
	if err := s.checkColumns(key, table, cols, required, &report.gap); err != nil {
		report.problems = append(report.problems, err)
	}
	collationProblems, err := s.checkBinaryCollations(ctx, r, key, table)
	if err != nil {
		return err
	}
	indexProblems, err := s.checkIndexes(ctx, r, key, table)
	if err != nil {
		return err
	}
	if len(collationProblems) > 0 || len(indexProblems) > 0 {
		report.indexOrCollation = true
	}
	report.problems = append(append(report.problems, collationProblems...), indexProblems...)
	return nil
}

// missingTableRemedy says how to create tables an empty database lacks. The
// reference DDL file names the default table names, so it is pointed at only
// when the store uses them.
func (s *Store) missingTableRemedy() string {
	return "oidcsql: create the missing tables with Store.Migrate, or by applying Store.Migrations() with your migration tool; " +
		"the reference DDL is " + s.ddlReference()
}

// ddlReference names where the DDL for this store's table names lives:
// the embedded file for the default names, [Store.Schema] otherwise.
func (s *Store) ddlReference() string {
	if s.names == defaultNames() {
		return "schema/" + s.dialect.name + "/v1.sql"
	}
	return "Store.Schema(), which carries the configured table names"
}

// checkBinaryCollations reports each [binaryCollationColumns] column of
// table whose MySQL collation compares case- or accent-insensitively.
// It checks nothing outside MySQL, where every comparison is byte-wise.
func (s *Store) checkBinaryCollations(ctx context.Context, r runner, key, table string) ([]error, error) {
	if s.dialect.name != "mysql" || len(binaryCollationColumns[key]) == 0 {
		return nil, nil
	}
	rows, err := r.QueryContext(ctx, mysqlCollationQuery, s.catalogTableName(table))
	if err != nil {
		return nil, fmt.Errorf("oidcsql: inspect collations for %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	collations := map[string]string{}
	for rows.Next() {
		var name string
		var collation databasesql.NullString
		if err := rows.Scan(&name, &collation); err != nil {
			return nil, fmt.Errorf("oidcsql: scan collations for %s: %w", table, err)
		}
		collations[name] = collation.String
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("oidcsql: iterate collations for %s: %w", table, err)
	}
	var problems []error
	for _, col := range binaryCollationColumns[key] {
		c, ok := collations[col]
		if !ok || c == "utf8mb4_bin" || c == "utf8mb4_0900_bin" {
			continue
		}
		problems = append(problems, fmt.Errorf("oidcsql: column %s of %s has collation %s, not utf8mb4_bin; apply migration %s",
			col, table, c, collationMigration(key)))
	}
	return problems, nil
}

// collationPinRelease is the release whose migration pins utf8mb4_bin on the
// identifier columns of every table that existed before it.
const collationPinRelease = "v1.3.0"

// collationMigration names the migration that pins the binary collation on
// the table's identifier columns: the one that created the table, or
// [collationPinRelease]'s for a table created before it.
func collationMigration(key string) string {
	i := releaseIndex(collationPinRelease)
	if j := releaseIndex(tableAddedIn(key)); j > i {
		i = j
	}
	return schemaReleases[i].migration
}

// releaseIndex returns the position of a release in [schemaReleases], or -1.
func releaseIndex(version string) int {
	return slices.IndexFunc(schemaReleases, func(r schemaRelease) bool { return r.version == version })
}

// tableMigrationHint names the migration that creates the table, or
// returns "" when it predates them.
func tableMigrationHint(dialect, key string) string {
	if v := tableAddedIn(key); v != "" {
		return migrationsHint(dialect, []string{schemaReleases[releaseIndex(v)].migration})
	}
	return ""
}

// migrationHint names the migrations that add the missing columns, or
// returns "" when every one predates them.
func migrationHint(dialect, key string, missing []string) string {
	var stems []string
	for _, r := range schemaReleases {
		for _, c := range missing {
			if columnAddedIn(key, c) == r.version {
				stems = append(stems, r.migration)
				break
			}
		}
	}
	return migrationsHint(dialect, stems)
}

// migrationsHint renders the error suffix that points at migration files.
func migrationsHint(dialect string, stems []string) string {
	switch len(stems) {
	case 0:
		return ""
	case 1:
		return "; apply migration " + stems[0] + " (schema/migrations/" + dialect + "/" + stems[0] + ".up.sql)"
	default:
		return "; apply migrations " + strings.Join(stems, ", ") + " (schema/migrations/" + dialect + "/)"
	}
}

func (s *Store) columnSet(ctx context.Context, table string) (map[string]bool, error) {
	return s.columnSetOn(ctx, dbRunner{db: s.db}, table)
}

// columnSetOn returns the columns of table read through r, empty when the
// table does not exist.
func (s *Store) columnSetOn(ctx context.Context, r runner, table string) (map[string]bool, error) {
	rows, err := r.QueryContext(ctx, s.columnListQuery(), s.catalogTableName(table))
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
		return "SELECT column_name FROM information_schema.columns WHERE table_schema = " + postgresResolvedSchema + " AND table_name = $1::text"
	default:
		return ""
	}
}

// postgresResolvedSchema is a scalar subquery, taking the table name as $1,
// that yields the first schema of the search_path holding the table: the one
// an unqualified statement resolves to.
const postgresResolvedSchema = "(SELECT n.nspname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace " +
	"WHERE c.relname = $1::text AND c.relkind IN ('r', 'p') AND n.nspname = ANY (current_schemas(false)) " +
	"ORDER BY array_position(current_schemas(false), n.nspname::name) LIMIT 1)"

// lookupScope names where the schema checks look for a table: the
// search_path schemas on PostgreSQL, the database on MySQL.
func (s *Store) lookupScope(ctx context.Context, r runner) string {
	var query, format string
	switch s.dialect.name {
	case "postgres":
		query, format = "SELECT array_to_string(current_schemas(false), ', ')", "in search_path schemas (%s)"
	case "mysql":
		query, format = "SELECT DATABASE()", "in database %s"
	default:
		return ""
	}
	var scope databasesql.NullString
	if err := r.QueryRowContext(ctx, query).Scan(&scope); err != nil || !scope.Valid {
		return ""
	}
	return fmt.Sprintf(format, scope.String)
}

// missingTableError reports a table absent from the scope the checks searched.
func missingTableError(table, scope, hint string) error {
	if scope != "" {
		scope = " " + scope
	}
	return fmt.Errorf("oidcsql: schema for %s is missing%s%s", table, scope, hint)
}

// mysqlCollationQuery reads the collation of each column of one MySQL table.
const mysqlCollationQuery = "SELECT column_name, collation_name FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ?"

// catalogTableName returns the name the catalog records for table. The
// adapter never quotes identifiers, so PostgreSQL folds a mixed-case
// [WithNaming] value to lower case when it creates and queries the table.
func (s *Store) catalogTableName(table string) string {
	if i := strings.LastIndex(table, "."); i >= 0 {
		table = table[i+1:]
	}
	if s.dialect.name == "postgres" {
		return strings.ToLower(table)
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
// plane. It is not part of [store.Store]: pass it to op.WithUserStore, or
// use [Store.UserPasswords] for PrimaryPassword.Store.
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
// time decisions (subject_mode today; future keys land on the same
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

// Compile-time guard: the library discovers registry support (the dynamic
// registration endpoint) by resolving the configured store to a
// [store.ClientRegistry], preferring an accessor and falling back to a type
// assertion on the store itself. Static client seeding goes through
// [store.StaticClientReconciler] instead. The resolution fails silently at
// runtime if the receiver loses any of the embedded ClientStore methods, so
// the assignment below pins the satisfaction at build time.
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
//
// A single-row query returns a [scanner] rather than *sql.Row because
// *sql.Row carries its failure in an unexported field: a transaction
// that has already settled has no way to report itself through one.
// [pickRunner] supplies the implementations.
type runner interface {
	ExecContext(ctx context.Context, query string, args ...any) (databasesql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*databasesql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) scanner
}
