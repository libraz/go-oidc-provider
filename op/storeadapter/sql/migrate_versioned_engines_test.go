//go:build testcontainers

package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"
	"hash/crc32"
	"io/fs"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"

	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

const versionTable = "oidc_schema_migrations"

// latestVersion is the number of migration files, and so the version a
// finished Migrate records.
const latestVersion = 6

// versionedEngine is one engine under test: a source of fresh databases and
// the engine-specific SQL the tests need.
type versionedEngine struct {
	name    string
	dialect oidcsql.Dialect
	// openDB returns a pool on a fresh, empty database.
	openDB func(t *testing.T) *databasesql.DB
	// sibling returns a second pool on the same database as db.
	sibling func(t *testing.T, db *databasesql.DB) *databasesql.DB
	// shape describes every table, column and index except those of exclude.
	shape func(t *testing.T, db *databasesql.DB, exclude string) []string
	// createVersionTable creates the version table with golang-migrate's DDL.
	createVersionTable string
	// placeholders is the VALUES list for (version, dirty).
	placeholders string
	// versionColumns is the expected (name, type, nullable) of the version table.
	versionColumns []string
	// versionColumnsQuery and constraintsQuery read the catalog for the version
	// table; both take the table name as their one argument.
	versionColumnsQuery string
	constraintsQuery    string
	// lock holds the advisory lock Migrate takes on a session of its own and
	// returns the release.
	lock func(t *testing.T, db *databasesql.DB) func()
}

func (e versionedEngine) newStore(t *testing.T, db *databasesql.DB) *oidcsql.Store {
	t.Helper()

	s, err := oidcsql.New(db, e.dialect)
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	return s
}

// migrationFiles returns the name and body of every up file, in order.
func migrationFiles(t *testing.T, s *oidcsql.Store) (names, bodies []string) {
	t.Helper()

	fsys := s.Migrations()
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		raw, err := fs.ReadFile(fsys, entry.Name())
		if err != nil {
			t.Fatalf("read %s: %v", entry.Name(), err)
		}
		names = append(names, entry.Name())
		bodies = append(bodies, string(raw))
	}
	if len(names) != latestVersion {
		t.Fatalf("%d migration files, want %d", len(names), latestVersion)
	}
	return names, bodies
}

// applyThrough applies the first n migration files by hand, one Exec per file
// as a migration tool sends it.
func (e versionedEngine) applyThrough(t *testing.T, s *oidcsql.Store, db *databasesql.DB, n int) {
	t.Helper()

	names, bodies := migrationFiles(t, s)
	for i := range n {
		if _, err := db.ExecContext(t.Context(), bodies[i]); err != nil {
			t.Fatalf("apply %s: %v", names[i], err)
		}
	}
}

// recordVersion creates the version table and records one row.
func (e versionedEngine) recordVersion(t *testing.T, db *databasesql.DB, version int64, dirty bool) {
	t.Helper()

	if _, err := db.ExecContext(t.Context(), e.createVersionTable); err != nil {
		t.Fatalf("create version table: %v", err)
	}
	if _, err := db.ExecContext(t.Context(),
		"INSERT INTO "+versionTable+" (version, dirty) VALUES ("+e.placeholders+")", version, dirty); err != nil {
		t.Fatalf("record version %d: %v", version, err)
	}
}

// versionRows returns the rows of the version table as "(version, dirty)".
func versionRows(t *testing.T, db *databasesql.DB) []string {
	t.Helper()

	rows, err := db.QueryContext(t.Context(), "SELECT version, dirty FROM "+versionTable+" ORDER BY version")
	if err != nil {
		t.Fatalf("read %s: %v", versionTable, err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var version int64
		var dirty bool
		if err := rows.Scan(&version, &dirty); err != nil {
			t.Fatalf("scan %s: %v", versionTable, err)
		}
		out = append(out, fmt.Sprintf("(%d, %t)", version, dirty))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate %s: %v", versionTable, err)
	}
	return out
}

func assertVersionRows(t *testing.T, db *databasesql.DB, want ...string) {
	t.Helper()

	if got := versionRows(t, db); !slices.Equal(got, want) {
		t.Errorf("%s rows = %v, want %v", versionTable, got, want)
	}
}

// tableCount counts the tables of the current database with one of names.
func tableCount(t *testing.T, db *databasesql.DB, names ...string) int {
	t.Helper()

	var n int
	for _, name := range names {
		var c int
		if err := db.QueryRowContext(t.Context(),
			"SELECT COUNT(*) FROM information_schema.tables WHERE table_name = "+tablePlaceholder(db)+" AND table_schema = "+schemaExpr(db),
			name).Scan(&c); err != nil {
			t.Fatalf("count table %s: %v", name, err)
		}
		n += c
	}
	return n
}

// tablePlaceholder and schemaExpr pick the engine's spelling from the driver.
func tablePlaceholder(db *databasesql.DB) string {
	if isMySQL(db) {
		return "?"
	}
	return "$1"
}

func schemaExpr(db *databasesql.DB) string {
	if isMySQL(db) {
		return "DATABASE()"
	}
	return "current_schema()"
}

func isMySQL(db *databasesql.DB) bool {
	_, ok := db.Driver().(*mysqldriver.MySQLDriver)
	return ok
}

// assertSameShape fails unless got and want describe the same schema.
func assertSameShape(t *testing.T, label string, got, want []string) {
	t.Helper()

	if slices.Equal(got, want) {
		return
	}
	var missing, extra []string
	for _, w := range want {
		if !slices.Contains(got, w) {
			missing = append(missing, w)
		}
	}
	for _, g := range got {
		if !slices.Contains(want, g) {
			extra = append(extra, g)
		}
	}
	t.Errorf("%s\nmissing: %v\nunexpected: %v", label, missing, extra)
}

// chainShape is the shape of a fresh database with every migration file
// applied by hand, which has no version table.
func (e versionedEngine) chainShape(t *testing.T, s *oidcsql.Store) []string {
	t.Helper()

	db := e.openDB(t)
	e.applyThrough(t, s, db, latestVersion)
	return e.shape(t, db, versionTable)
}

// migrateTimeout bounds one Migrate: MySQL 000004 alters every table.
const migrateTimeout = 2 * time.Minute

func (e versionedEngine) migrate(t *testing.T, s *oidcsql.Store) error {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), migrateTimeout)
	defer cancel()
	return s.Migrate(ctx)
}

func queryLines(t *testing.T, db *databasesql.DB, query string, args ...any) []string {
	t.Helper()

	rows, err := db.QueryContext(t.Context(), query, args...)
	if err != nil {
		t.Fatalf("query %q: %v", query, err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out = append(out, line)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	return out
}

// lockKey is golang-migrate's advisory lock key derivation.
func lockKey(s string) uint32 {
	return crc32.ChecksumIEEE([]byte(s)) * 1486364155
}

// mysqlEngine boots one MySQL container and returns the engine over it.
func mysqlEngine(t *testing.T) versionedEngine {
	t.Helper()

	// The factory hands out each database's config here so a test can open a
	// second pool on it.
	var configs sync.Map
	openDB := newMySQLDBFactory(t, false, func(cfg *mysqldriver.Config) { configs.Store(cfg.DBName, cfg.Clone()) })

	return versionedEngine{
		name:    "mysql",
		dialect: oidcsql.MySQL(),
		openDB:  openDB,
		sibling: func(t *testing.T, db *databasesql.DB) *databasesql.DB {
			t.Helper()
			var name string
			if err := db.QueryRowContext(t.Context(), "SELECT DATABASE()").Scan(&name); err != nil {
				t.Fatalf("SELECT DATABASE(): %v", err)
			}
			cfg, ok := configs.Load(name)
			if !ok {
				t.Fatalf("no config recorded for database %s", name)
			}
			other, err := databasesql.Open("mysql", cfg.(*mysqldriver.Config).FormatDSN())
			if err != nil {
				t.Fatalf("open sibling: %v", err)
			}
			t.Cleanup(func() { _ = other.Close() })
			return other
		},
		shape: func(t *testing.T, db *databasesql.DB, exclude string) []string {
			t.Helper()
			out := queryLines(t, db, `
				SELECT CONCAT('column ', TABLE_NAME, '.', COLUMN_NAME, ' ', COLUMN_TYPE, ' nullable=', IS_NULLABLE,
					' collation=', IFNULL(COLLATION_NAME, '-'), ' default=', IFNULL(COLUMN_DEFAULT, 'NULL'))
				FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME <> ?`, exclude)
			out = append(out, queryLines(t, db, `
				SELECT CONCAT('index ', TABLE_NAME, '.', INDEX_NAME, '[', SEQ_IN_INDEX, ']=', COLUMN_NAME, ' nonunique=', NON_UNIQUE)
				FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME <> ?`, exclude)...)
			slices.Sort(out)
			return out
		},
		createVersionTable:  "CREATE TABLE `" + versionTable + "` (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL)",
		placeholders:        "?, ?",
		versionColumns:      []string{"version bigint NO", "dirty tinyint(1) NO"},
		versionColumnsQuery: `SELECT CONCAT(column_name, ' ', column_type, ' ', is_nullable) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? ORDER BY ordinal_position`,
		constraintsQuery: `SELECT CONCAT(tc.constraint_type, ' ', GROUP_CONCAT(k.column_name ORDER BY k.ordinal_position))
			FROM information_schema.table_constraints tc
			JOIN information_schema.key_column_usage k USING (constraint_schema, constraint_name, table_name)
			WHERE tc.table_schema = DATABASE() AND tc.table_name = ? GROUP BY tc.constraint_name, tc.constraint_type`,
		lock: func(t *testing.T, db *databasesql.DB) func() {
			t.Helper()
			var name string
			if err := db.QueryRowContext(t.Context(), "SELECT DATABASE()").Scan(&name); err != nil {
				t.Fatalf("SELECT DATABASE(): %v", err)
			}
			key := strconv.FormatUint(uint64(lockKey(name+":"+versionTable)), 10)
			conn, err := db.Conn(t.Context())
			if err != nil {
				t.Fatalf("holder connection: %v", err)
			}
			var got int
			if err := conn.QueryRowContext(t.Context(), "SELECT GET_LOCK(?, 0)", key).Scan(&got); err != nil || got != 1 {
				t.Fatalf("GET_LOCK(%s) = %d, %v; want 1", key, got, err)
			}
			return func() {
				_, _ = conn.ExecContext(context.Background(), "SELECT RELEASE_LOCK(?)", key)
				_ = conn.Close()
			}
		},
	}
}

// postgresEngine boots one PostgreSQL container and returns the engine over it.
func postgresEngine(t *testing.T) versionedEngine {
	t.Helper()

	var dsns sync.Map
	openDB := newPostgresDBFactory(t, func(dsn string) string {
		if u, err := url.Parse(dsn); err == nil {
			dsns.Store(strings.TrimPrefix(u.Path, "/"), dsn)
		}
		return dsn
	})

	return versionedEngine{
		name:    "postgres",
		dialect: oidcsql.Postgres(),
		openDB:  openDB,
		sibling: func(t *testing.T, db *databasesql.DB) *databasesql.DB {
			t.Helper()
			var name string
			if err := db.QueryRowContext(t.Context(), "SELECT current_database()").Scan(&name); err != nil {
				t.Fatalf("SELECT current_database(): %v", err)
			}
			dsn, ok := dsns.Load(name)
			if !ok {
				t.Fatalf("no DSN recorded for database %s", name)
			}
			other, err := databasesql.Open("pgx", dsn.(string))
			if err != nil {
				t.Fatalf("open sibling: %v", err)
			}
			t.Cleanup(func() { _ = other.Close() })
			return other
		},
		shape:               postgresSchemaShape,
		createVersionTable:  "CREATE TABLE " + versionTable + " (version bigint NOT NULL PRIMARY KEY, dirty boolean NOT NULL)",
		placeholders:        "$1, $2",
		versionColumns:      []string{"version bigint NO", "dirty boolean NO"},
		versionColumnsQuery: `SELECT column_name || ' ' || data_type || ' ' || is_nullable FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 ORDER BY ordinal_position`,
		constraintsQuery: `SELECT tc.constraint_type || ' ' || string_agg(k.column_name, ',' ORDER BY k.ordinal_position)
			FROM information_schema.table_constraints tc
			JOIN information_schema.key_column_usage k USING (constraint_schema, constraint_name, table_name)
			WHERE tc.table_schema = current_schema() AND tc.table_name = $1 GROUP BY tc.constraint_name, tc.constraint_type`,
		lock: func(t *testing.T, db *databasesql.DB) func() {
			t.Helper()
			var database, schema string
			if err := db.QueryRowContext(t.Context(), "SELECT current_database(), current_schema()").Scan(&database, &schema); err != nil {
				t.Fatalf("read database and schema: %v", err)
			}
			key := int64(lockKey(schema + "\x00" + versionTable + "\x00" + database))
			conn, err := db.Conn(t.Context())
			if err != nil {
				t.Fatalf("holder connection: %v", err)
			}
			if _, err := conn.ExecContext(t.Context(), "SELECT pg_advisory_lock($1)", key); err != nil {
				t.Fatalf("pg_advisory_lock(%d): %v", key, err)
			}
			return func() {
				_, _ = conn.ExecContext(context.Background(), "SELECT pg_advisory_unlock($1)", key)
				_ = conn.Close()
			}
		},
	}
}

func TestMigrate_VersionedMySQL(t *testing.T) {
	t.Parallel()

	runVersionedEngineTests(t, mysqlEngine(t))
}

func TestMigrate_VersionedPostgres(t *testing.T) {
	t.Parallel()

	runVersionedEngineTests(t, postgresEngine(t))
}

func runVersionedEngineTests(t *testing.T, e versionedEngine) {
	t.Helper()

	t.Run("empty database reaches the chain schema", func(t *testing.T) {
		t.Parallel()

		db := e.openDB(t)
		s := e.newStore(t, db)
		if err := e.migrate(t, s); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		assertSameShape(t, "Migrate does not reach the migration chain's schema",
			e.shape(t, db, versionTable), e.chainShape(t, s))
		assertVersionRows(t, db, "(6, false)")
	})

	// A file before the recorded version is never re-run: each of 000002,
	// 000005 and 000006 adds a column, which fails a second time.
	t.Run("applies only later files", func(t *testing.T) {
		t.Parallel()

		for k := 1; k <= 5; k++ {
			t.Run(fmt.Sprintf("recorded_%d", k), func(t *testing.T) {
				t.Parallel()

				db := e.openDB(t)
				s := e.newStore(t, db)
				e.applyThrough(t, s, db, k)
				e.recordVersion(t, db, int64(k), false)
				if err := e.migrate(t, s); err != nil {
					t.Fatalf("Migrate: %v", err)
				}
				assertSameShape(t, "Migrate from a recorded version does not reach the chain's schema",
					e.shape(t, db, versionTable), e.chainShape(t, s))
				assertVersionRows(t, db, "(6, false)")
			})
		}
	})

	t.Run("twice keeps one row", func(t *testing.T) {
		t.Parallel()

		db := e.openDB(t)
		s := e.newStore(t, db)
		for i := range 2 {
			if err := e.migrate(t, s); err != nil {
				t.Fatalf("Migrate %d: %v", i+1, err)
			}
		}
		assertVersionRows(t, db, "(6, false)")
	})

	t.Run("refuses a dirty version", func(t *testing.T) {
		t.Parallel()

		db := e.openDB(t)
		s := e.newStore(t, db)
		e.applyThrough(t, s, db, 4)
		e.recordVersion(t, db, 4, true)
		before := e.shape(t, db, "")
		err := e.migrate(t, s)
		if err == nil {
			t.Fatal("Migrate accepted a dirty version")
		}
		for _, want := range []string{
			"dirty at version 4",
			"UPDATE oidc_schema_migrations SET version = 4, dirty = false",
			"migrate force 4",
		} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("Migrate error = %v\nwant it to contain %q", err, want)
			}
		}
		assertSameShape(t, "Migrate changed a dirty database", e.shape(t, db, ""), before)
		assertVersionRows(t, db, "(4, true)")
	})

	t.Run("version table matches golang-migrate", func(t *testing.T) {
		t.Parallel()

		db := e.openDB(t)
		s := e.newStore(t, db)
		if err := e.migrate(t, s); err != nil {
			t.Fatalf("Migrate: %v", err)
		}
		if got := queryLines(t, db, e.versionColumnsQuery, versionTable); !slices.Equal(got, e.versionColumns) {
			t.Errorf("%s columns = %v, want %v", versionTable, got, e.versionColumns)
		}
		if got, want := queryLines(t, db, e.constraintsQuery, versionTable), []string{"PRIMARY KEY version"}; !slices.Equal(got, want) {
			t.Errorf("%s constraints = %v, want %v", versionTable, got, want)
		}
	})

	// Two pools on one database migrate at once; the advisory lock lets the
	// second wait and then find the work done.
	t.Run("concurrent calls agree", func(t *testing.T) {
		t.Parallel()

		db := e.openDB(t)
		stores := []*oidcsql.Store{e.newStore(t, db), e.newStore(t, e.sibling(t, db))}
		errs := make([]error, len(stores))
		var wg sync.WaitGroup
		for i, s := range stores {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), migrateTimeout)
				defer cancel()
				errs[i] = s.Migrate(ctx)
			}()
		}
		wg.Wait()
		for i, err := range errs {
			if err != nil {
				t.Errorf("Migrate %d: %v", i, err)
			}
		}
		assertVersionRows(t, db, "(6, false)")
		assertSameShape(t, "concurrent Migrate calls do not reach the chain's schema",
			e.shape(t, db, versionTable), e.chainShape(t, stores[0]))
	})

	t.Run("waits for the lock until ctx ends", func(t *testing.T) {
		t.Parallel()

		db := e.openDB(t)
		s := e.newStore(t, db)
		release := e.lock(t, db)
		released := false
		defer func() {
			if !released {
				release()
			}
		}()

		ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
		defer cancel()
		err := s.Migrate(ctx)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Migrate while the lock is held = %v, want context.DeadlineExceeded", err)
		}
		if n := tableCount(t, db, versionTable, "oidc_clients"); n != 0 {
			t.Errorf("Migrate created %d tables before it held the lock", n)
		}

		release()
		released = true
		if err := e.migrate(t, s); err != nil {
			t.Fatalf("Migrate after the lock was released: %v", err)
		}
		assertVersionRows(t, db, "(6, false)")
	})
}

// A MySQL connection without multiStatements applies the files: Migrate sends
// one statement at a time.
func TestMigrate_MySQLWithoutMultiStatements(t *testing.T) {
	t.Parallel()

	openDB := newMySQLDBFactory(t, false, func(cfg *mysqldriver.Config) { cfg.MultiStatements = false })
	db := openDB(t)
	if _, err := db.ExecContext(t.Context(), "SELECT 1; SELECT 2"); err == nil {
		t.Fatal("the pool accepts multiple statements; the test needs one that does not")
	}
	s, err := oidcsql.New(db, oidcsql.MySQL())
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), migrateTimeout)
	defer cancel()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := s.ValidateSchema(ctx); err != nil {
		t.Errorf("ValidateSchema after Migrate: %v", err)
	}
	assertVersionRows(t, db, "(6, false)")
}
