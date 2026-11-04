package oidcsql

import (
	"context"
	databasesql "database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"hash/crc32"
	"io/fs"
	"strconv"
	"strings"
	"time"
)

// versionTableSuffix follows the [WithTablePrefix] in the name of the table
// [Store.Migrate] records the last applied migration in.
const versionTableSuffix = "schema_migrations"

// migrateCleanupTimeout bounds the statements that release the lock or roll
// back once the caller's ctx may be done.
const migrateCleanupTimeout = 5 * time.Second

// lockKeySalt is the multiplier golang-migrate applies to the CRC-32 of the
// lock input.
const lockKeySalt uint32 = 1486364155

// errEmptyPrefix is the refusal of [Store.Migrate] under WithTablePrefix("").
var errEmptyPrefix = errors.New(`oidcsql: Migrate needs a table prefix: with WithTablePrefix("") the version table would be ` +
	`"schema_migrations", golang-migrate's default table; apply Store.Migrations() with your migration tool instead`)

// lockKey derives the advisory lock key golang-migrate takes for the same
// input, so the two exclude each other. The product wraps around in uint32.
func lockKey(s string) uint32 {
	return crc32.ChecksumIEEE([]byte(s)) * lockKeySalt
}

// versionTable is the name of the table [Store.Migrate] records in.
func (s *Store) versionTable() string {
	return s.prefix + versionTableSuffix
}

// connRunner adapts *sql.Conn to [runner], so the schema checks read the
// catalog on the connection Migrate holds.
type connRunner struct{ conn *databasesql.Conn }

func (r connRunner) ExecContext(ctx context.Context, query string, args ...any) (databasesql.Result, error) {
	return r.conn.ExecContext(ctx, query, args...)
}

func (r connRunner) QueryContext(ctx context.Context, query string, args ...any) (*databasesql.Rows, error) {
	return r.conn.QueryContext(ctx, query, args...)
}

func (r connRunner) QueryRowContext(ctx context.Context, query string, args ...any) scanner {
	return r.conn.QueryRowContext(ctx, query, args...)
}

var _ runner = connRunner{}

// migrator is one run of [Store.Migrate]. Every statement goes through conn:
// the session holds the advisory lock, and on a pool of one connection or an
// in-memory SQLite database any other connection would block or see another
// database.
type migrator struct {
	s     *Store
	conn  *databasesql.Conn
	begin func(ctx context.Context) (*databasesql.Tx, error)
	r     connRunner
	table string
}

// migrate is [Store.Migrate].
func (s *Store) migrate(ctx context.Context) error {
	if s.prefix == "" {
		return errEmptyPrefix
	}
	sess, err := s.openMigrationSession(ctx)
	if err != nil {
		return fmt.Errorf("oidcsql: Migrate: open a connection: %w", err)
	}
	defer sess.release()
	conn := sess.conn
	m := &migrator{s: s, conn: conn, begin: sess.begin, r: connRunner{conn: conn}, table: s.versionTable()}
	unlock, err := m.lock(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if err := m.run(ctx); err != nil {
		return err
	}
	return s.validateKeysOn(ctx, m.r, knownNamingKeys...)
}

// run decides what the database needs and applies it. Every refusal comes
// before the first statement that writes.
func (m *migrator) run(ctx context.Context) error {
	version, dirty, recorded, err := m.currentVersion(ctx)
	if err != nil {
		return err
	}
	latest := int64(len(schemaReleases) + 1)
	if recorded && dirty {
		return m.dirtyError(version)
	}
	if recorded && version > latest {
		return nil
	}
	var from int64
	if recorded {
		from = version
	}
	hasTables, err := m.checkTables(ctx, from)
	if err != nil {
		return err
	}
	if !recorded && hasTables {
		return m.baseline(ctx, latest)
	}
	files := m.s.Migrations()
	for n := from + 1; n <= latest; n++ {
		file := migrationStem(n) + ".up.sql"
		raw, err := fs.ReadFile(files, file)
		if err != nil {
			return fmt.Errorf("oidcsql: Migrate: read %s: %w", file, err)
		}
		if err := m.apply(ctx, n, file, splitStatements(string(raw))); err != nil {
			return err
		}
	}
	return nil
}

// currentVersion reads the version table without creating it. recorded is
// false when the table is absent or empty.
func (m *migrator) currentVersion(ctx context.Context) (version int64, dirty, recorded bool, err error) {
	cols, err := m.s.columnSetOn(ctx, m.r, m.table)
	if err != nil {
		return 0, false, false, err
	}
	if len(cols) == 0 {
		return 0, false, false, nil
	}
	return m.readVersion(ctx, m.r)
}

// readVersion reads the one row of the version table through r.
func (m *migrator) readVersion(ctx context.Context, r runner) (version int64, dirty, recorded bool, err error) {
	err = r.QueryRowContext(ctx, "SELECT version, dirty FROM "+m.table+" LIMIT 1").Scan(&version, &dirty)
	if errors.Is(err, databasesql.ErrNoRows) {
		return 0, false, false, nil
	}
	if err != nil {
		return 0, false, false, fmt.Errorf("oidcsql: Migrate: read version table %s: %w", m.table, err)
	}
	return version, dirty, true, nil
}

// checkTables refuses a database where a table on one of the adapter's names
// lacks a column of the first release, or, when version records a migration,
// a table of the first release is missing. It reports whether any adapter
// table exists.
func (m *migrator) checkTables(ctx context.Context, version int64) (bool, error) {
	required := ddlColumns(m.s.dialect)
	found := false
	for _, key := range knownNamingKeys {
		table := m.s.names.byKey(key)
		cols, err := m.s.columnSetOn(ctx, m.r, table)
		if err != nil {
			return false, err
		}
		if len(cols) == 0 {
			if version >= 1 && tableAddedIn(key) == "" {
				return false, fmt.Errorf("oidcsql: Migrate changed nothing: version table %s records version %d but table %s "+
					"created by migration %s is missing; the version table belongs to another history or another database",
					m.table, version, table, migrationNumber(baselineMigration))
			}
			continue
		}
		found = true
		if missing := missingBaselineColumns(key, cols, required[key]); len(missing) > 0 {
			var gap releaseGap
			return false, fmt.Errorf("oidcsql: Migrate changed nothing: table %s exists but is not the adapter's table "+
				"(missing baseline columns: %s): %w", table, strings.Join(missing, ", "),
				m.s.checkColumns(key, table, cols, required[key], &gap))
		}
	}
	return found, nil
}

// missingBaselineColumns lists the columns of the first release that cols lacks.
func missingBaselineColumns(key string, cols map[string]bool, required []string) []string {
	var missing []string
	for _, col := range required {
		if !cols[col] && columnAddedIn(key, col) == "" {
			missing = append(missing, col)
		}
	}
	return missing
}

// baseline records latest for a database that has the adapter's tables but
// no version, when the schema checks pass on it, and refuses otherwise.
func (m *migrator) baseline(ctx context.Context, latest int64) error {
	report, err := m.s.inspectSchema(ctx, m.r, knownNamingKeys...)
	if err != nil {
		return err
	}
	if verr := report.err(); verr != nil {
		return m.unrecordedError(report, verr)
	}
	return m.apply(ctx, latest, "the version record", nil)
}

// unrecordedError refuses a database with the adapter's tables, no version
// and a schema that fails the checks. It names the version to record only when
// the estimate can be trusted: on MySQL an index or collation problem may
// belong to a release the estimate skips.
func (m *migrator) unrecordedError(report schemaReport, verr error) error {
	head := fmt.Sprintf("oidcsql: Migrate changed nothing: the database has the adapter's tables but no version table %s, "+
		"and the schema does not match this release:", m.table)
	version, stem, number, ok := report.gap.applied()
	if ok && (m.s.dialect.name != "mysql" || !report.indexOrCollation) {
		return fmt.Errorf("%s\n%w\nIf the schema is at release %s (migration %s), record it with: "+
			"INSERT INTO %s (version, dirty) VALUES (%d, false); and run Migrate again. "+
			"The release is estimated from missing columns and tables only", head, verr, version, migrationNumber(stem), m.table, number)
	}
	return fmt.Errorf("%s\n%w\nApply the migrations named above, or create the version table at the release the schema is at, "+
		"then run Migrate again", head, verr)
}

// dirtyError refuses a version a MySQL file left part-way.
func (m *migrator) dirtyError(version int64) error {
	return fmt.Errorf("oidcsql: Migrate changed nothing: version table %s is dirty at version %d: migration %s stopped part-way. "+
		"Check which of its statements applied, finish or undo them by hand, then run: "+
		"UPDATE %s SET version = %d, dirty = false (or: migrate force %d) and run Migrate again",
		m.table, version, migrationFileName(version), m.table, version, version)
}

// migrationStem returns the stem of migration file n, 1 being the baseline.
func migrationStem(n int64) string {
	if n == 1 {
		return baselineMigration
	}
	return schemaReleases[n-2].migration
}

// migrationFileName names migration file n, or gives its zero-padded number
// when this release ships no such file.
func migrationFileName(n int64) string {
	if n < 1 || n > int64(len(schemaReleases)+1) {
		return fmt.Sprintf("%06d", n)
	}
	return migrationStem(n) + ".up.sql"
}

// apply runs the statements of file n and records n. With no statements it
// only records n.
func (m *migrator) apply(ctx context.Context, n int64, file string, stmts []string) error {
	switch m.s.dialect.name {
	case "sqlite":
		return m.applySQLite(ctx, n, file, stmts)
	case "postgres":
		return m.applyPostgres(ctx, n, file, stmts)
	default:
		return m.applyMySQL(ctx, n, file, stmts)
	}
}

// applySQLite runs one file in a transaction opened with BEGIN IMMEDIATE,
// which [databasesql.Conn.BeginTx] cannot issue: it takes the write lock
// before re-reading the version, so a concurrent Migrate waits and then skips
// the file.
func (m *migrator) applySQLite(ctx context.Context, n int64, file string, stmts []string) error {
	if _, err := m.conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("oidcsql: Migrate: begin %s: %w", file, err)
	}
	err := m.step(ctx, m.r, n, file, stmts)
	if err == nil {
		if _, err = m.conn.ExecContext(ctx, "COMMIT"); err != nil {
			err = fmt.Errorf("oidcsql: Migrate: commit %s: %w", file, err)
		}
	}
	if err != nil {
		m.rollbackSQLite(ctx)
		return err
	}
	return nil
}

// rollbackSQLite ends the open transaction, or discards the connection when it
// cannot, since a connection inside a transaction must not return to the pool.
func (m *migrator) rollbackSQLite(ctx context.Context) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), migrateCleanupTimeout)
	defer cancel()
	if _, err := m.conn.ExecContext(cctx, "ROLLBACK"); err != nil {
		m.discard()
	}
}

// applyPostgres runs one file and its version record in one transaction.
func (m *migrator) applyPostgres(ctx context.Context, n int64, file string, stmts []string) error {
	tx, err := m.begin(ctx)
	if err != nil {
		return fmt.Errorf("oidcsql: Migrate: begin %s: %w", file, err)
	}
	if err := m.step(ctx, txRunner{tx: tx}, n, file, stmts); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("oidcsql: Migrate: commit %s: %w", file, err)
	}
	return nil
}

// step creates the version table if needed, re-reads the version and, unless
// n is already recorded, runs the statements and records n, all through r.
func (m *migrator) step(ctx context.Context, r runner, n int64, file string, stmts []string) error {
	if err := m.ensureVersionTable(ctx, r); err != nil {
		return err
	}
	version, _, recorded, err := m.readVersion(ctx, r)
	if err != nil {
		return err
	}
	if recorded && version >= n {
		return nil
	}
	for i, stmt := range stmts {
		if _, err := r.ExecContext(ctx, stmt); err != nil {
			return statementError(file, i, stmts, err)
		}
	}
	return m.writeVersion(ctx, r, n, false)
}

// applyMySQL runs one file between a dirty and a clean record of n, because
// MySQL commits each DDL statement implicitly.
func (m *migrator) applyMySQL(ctx context.Context, n int64, file string, stmts []string) error {
	if err := m.ensureVersionTable(ctx, m.r); err != nil {
		return err
	}
	if len(stmts) > 0 {
		if err := m.writeVersionTx(ctx, n, true); err != nil {
			return err
		}
	}
	for i, stmt := range stmts {
		if _, err := m.conn.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("%w; version table %s left dirty at %d", statementError(file, i, stmts, err), m.table, n)
		}
	}
	return m.writeVersionTx(ctx, n, false)
}

// statementError reports the failure of statement i of file.
func statementError(file string, i int, stmts []string, err error) error {
	return fmt.Errorf("oidcsql: applying %s statement %d of %d %q: %w", file, i+1, len(stmts), trimForError(stmts[i]), err)
}

// writeVersionTx replaces the version row in a transaction of its own, so a
// reader never sees the table empty.
func (m *migrator) writeVersionTx(ctx context.Context, n int64, dirty bool) error {
	tx, err := m.begin(ctx)
	if err != nil {
		return fmt.Errorf("oidcsql: Migrate: begin version update: %w", err)
	}
	if err := m.writeVersion(ctx, txRunner{tx: tx}, n, dirty); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("oidcsql: Migrate: commit version update: %w", err)
	}
	return nil
}

// writeVersion replaces the one row of the version table through r.
func (m *migrator) writeVersion(ctx context.Context, r runner, n int64, dirty bool) error {
	placeholders := "?, ?"
	if m.s.dialect.usesDollar {
		placeholders = "$1, $2"
	}
	if _, err := r.ExecContext(ctx, "DELETE FROM "+m.table); err != nil {
		return fmt.Errorf("oidcsql: Migrate: clear version table %s: %w", m.table, err)
	}
	if _, err := r.ExecContext(ctx, "INSERT INTO "+m.table+" (version, dirty) VALUES ("+placeholders+")", n, dirty); err != nil {
		return fmt.Errorf("oidcsql: Migrate: record version %d in %s: %w", n, m.table, err)
	}
	return nil
}

// ensureVersionTable creates the version table with golang-migrate's columns
// for the dialect. SQLite's unique index carries the table name because index
// names are unique across a SQLite database.
func (m *migrator) ensureVersionTable(ctx context.Context, r runner) error {
	var stmts []string
	switch m.s.dialect.name {
	case "mysql":
		stmts = []string{"CREATE TABLE IF NOT EXISTS `" + m.table + "` (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL)"}
	case "postgres":
		stmts = []string{"CREATE TABLE IF NOT EXISTS " + m.table + " (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL)"}
	default:
		stmts = []string{
			"CREATE TABLE IF NOT EXISTS " + m.table + " (version uint64, dirty bool)",
			"CREATE UNIQUE INDEX IF NOT EXISTS " + m.table + "_version_unique ON " + m.table + " (version)",
		}
	}
	for _, stmt := range stmts {
		if _, err := r.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("oidcsql: Migrate: create version table %s: %w", m.table, err)
		}
	}
	return nil
}

// lock takes the advisory lock golang-migrate takes for the version table, and
// returns its release. SQLite has none; its writes serialise on BEGIN
// IMMEDIATE.
func (m *migrator) lock(ctx context.Context) (func(), error) {
	switch m.s.dialect.name {
	case "mysql":
		return m.lockMySQL(ctx)
	case "postgres":
		return m.lockPostgres(ctx)
	default:
		return func() {}, nil
	}
}

// lockMySQL waits for GET_LOCK one second at a time on the server, checking
// ctx between calls, so no wait outlives the caller.
func (m *migrator) lockMySQL(ctx context.Context) (func(), error) {
	var database databasesql.NullString
	if err := m.conn.QueryRowContext(ctx, "SELECT DATABASE()").Scan(&database); err != nil {
		return nil, fmt.Errorf("oidcsql: Migrate: read the database name: %w", err)
	}
	if !database.Valid {
		return nil, errors.New("oidcsql: Migrate needs a database: SELECT DATABASE() returned NULL; name one in the DSN")
	}
	name := strconv.FormatUint(uint64(lockKey(database.String+":"+m.table)), 10)
	for {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("oidcsql: Migrate: wait for lock %s: %w", name, err)
		}
		var got databasesql.NullInt64
		if err := m.conn.QueryRowContext(ctx, "SELECT GET_LOCK(?, 1)", name).Scan(&got); err != nil {
			return nil, fmt.Errorf("oidcsql: Migrate: take lock %s: %w", name, errors.Join(ctx.Err(), err))
		}
		if !got.Valid {
			return nil, fmt.Errorf("oidcsql: Migrate: GET_LOCK(%s) returned NULL", name)
		}
		if got.Int64 == 1 {
			return func() { m.unlock(ctx, "SELECT RELEASE_LOCK(?)", name) }, nil
		}
	}
}

// lockPostgres waits in pg_advisory_lock; the driver cancels the wait with
// ctx.
func (m *migrator) lockPostgres(ctx context.Context) (func(), error) {
	var database string
	var schema databasesql.NullString
	if err := m.conn.QueryRowContext(ctx, "SELECT current_database(), current_schema()").Scan(&database, &schema); err != nil {
		return nil, fmt.Errorf("oidcsql: Migrate: read the database and schema: %w", err)
	}
	if !schema.Valid {
		return nil, errors.New("oidcsql: Migrate needs a schema: current_schema() is NULL; put an existing schema first in the search_path")
	}
	key := int64(lockKey(schema.String + "\x00" + m.table + "\x00" + database))
	if _, err := m.conn.ExecContext(ctx, "SELECT pg_advisory_lock($1)", key); err != nil {
		return nil, fmt.Errorf("oidcsql: Migrate: take advisory lock %d: %w", key, errors.Join(ctx.Err(), err))
	}
	return func() { m.unlock(ctx, "SELECT pg_advisory_unlock($1)", key) }, nil
}

// unlock releases the advisory lock even when ctx is done. When that fails the
// connection is discarded instead: ending the session releases the lock.
func (m *migrator) unlock(ctx context.Context, query string, arg any) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), migrateCleanupTimeout)
	defer cancel()
	if _, err := m.conn.ExecContext(cctx, query, arg); err != nil {
		m.discard()
	}
}

// discard closes the connection instead of returning it to the pool.
func (m *migrator) discard() {
	_ = m.conn.Raw(func(any) error { return driver.ErrBadConn })
}
