//nolint:testpackage // tests reference the unexported version table, lock key and migration helpers.
package oidcsql

import (
	"context"
	databasesql "database/sql"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// newVersionedSQLite returns a store on an empty file-backed SQLite database.
func newVersionedSQLite(t *testing.T, opts ...Option) (*Store, *databasesql.DB) {
	t.Helper()

	db := openMigrationSQLite(t)
	s, err := New(db, SQLite(), opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s, db
}

// recordVersion creates a version table the way golang-migrate's SQLite
// driver does and records one row in it.
func recordVersion(t *testing.T, db *databasesql.DB, table string, version int64, dirty bool) {
	t.Helper()

	execAll(t, db,
		"CREATE TABLE "+table+" (version uint64, dirty bool)",
		"CREATE UNIQUE INDEX "+table+"_version_unique ON "+table+" (version)")
	if _, err := db.ExecContext(t.Context(), "INSERT INTO "+table+" (version, dirty) VALUES (?, ?)", version, dirty); err != nil { //nolint:gosec // table is a constant of this test file.
		t.Fatalf("record version %d: %v", version, err)
	}
}

// tableExists reports whether SQLite has a table of that name.
func tableExists(t *testing.T, db *databasesql.DB, table string) bool {
	t.Helper()

	var n int
	if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&n); err != nil {
		t.Fatalf("look up table %s: %v", table, err)
	}
	return n == 1
}

// versionRows returns the rows of the version table as "(version, dirty)",
// nil when the table does not exist.
func versionRows(t *testing.T, db *databasesql.DB, table string) []string {
	t.Helper()

	if !tableExists(t, db, table) {
		return nil
	}
	rows, err := db.QueryContext(t.Context(), "SELECT version, dirty FROM "+table+" ORDER BY version") //nolint:gosec // table is a constant of this test file.
	if err != nil {
		t.Fatalf("read %s: %v", table, err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var version int64
		var dirty bool
		if err := rows.Scan(&version, &dirty); err != nil {
			t.Fatalf("scan %s: %v", table, err)
		}
		out = append(out, fmt.Sprintf("(%d, %t)", version, dirty))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate %s: %v", table, err)
	}
	return out
}

// chainShape is the shape of a database every migration file of s was applied
// to, without a version table.
func chainShape(t *testing.T, s *Store) []string {
	t.Helper()

	db := openMigrationSQLite(t)
	applyMigrationChain(t, db, s.Migrations(), false)
	return sqliteSchemaShape(t, db)
}

// assertVersionRows fails unless the version table holds exactly want.
func assertVersionRows(t *testing.T, db *databasesql.DB, table string, want ...string) {
	t.Helper()

	if got := versionRows(t, db, table); !slices.Equal(got, want) {
		t.Errorf("%s rows = %v, want %v", table, got, want)
	}
}

// assertShape fails unless got and want describe the same schema.
func assertShape(t *testing.T, label string, got, want []string) {
	t.Helper()

	if !slices.Equal(got, want) {
		t.Errorf("%s\nmissing: %v\nunexpected: %v", label, setDifference(want, got), setDifference(got, want))
	}
}

func TestAdvisoryLockKey(t *testing.T) {
	t.Parallel()

	for input, want := range map[string]uint32{
		"oidc_admin:oidc_schema_migrations":              353752620,
		"public\x00oidc_schema_migrations\x00oidc_admin": 3004714622,
		"oidc_t_1:oidc_schema_migrations":                2530023178,
		"public\x00oidc_schema_migrations\x00oidc_t_1":   4190331363,
	} {
		if got := lockKey(input); got != want {
			t.Errorf("lockKey(%q) = %d, want %d", input, got, want)
		}
	}
}

func TestMigrate_EmptyDatabaseReachesTheChainSchema(t *testing.T) {
	t.Parallel()

	s, db := newVersionedSQLite(t)
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	assertShape(t, "Migrate does not reach the migration chain's schema",
		excludeTable(sqliteSchemaShape(t, db), s.versionTable()), chainShape(t, s))
	assertVersionRows(t, db, "oidc_schema_migrations", "(6, false)")
}

// A file before the recorded version is never re-run: each of 000002, 000005
// and 000006 adds a column, which fails a second time.
func TestMigrate_AppliesOnlyLaterFiles(t *testing.T) {
	t.Parallel()

	for k := 1; k <= 5; k++ {
		t.Run(fmt.Sprintf("recorded_%d", k), func(t *testing.T) {
			t.Parallel()

			s, db := newVersionedSQLite(t)
			applyMigrationsThrough(t, s, db, k)
			recordVersion(t, db, s.versionTable(), int64(k), false)
			if err := s.Migrate(t.Context()); err != nil {
				t.Fatalf("Migrate: %v", err)
			}
			assertShape(t, "Migrate from a recorded version does not reach the chain's schema",
				excludeTable(sqliteSchemaShape(t, db), s.versionTable()), chainShape(t, s))
			assertVersionRows(t, db, s.versionTable(), "(6, false)")
		})
	}
}

func TestMigrate_TwiceKeepsOneRow(t *testing.T) {
	t.Parallel()

	s, db := newVersionedSQLite(t)
	for i := range 2 {
		if err := s.Migrate(t.Context()); err != nil {
			t.Fatalf("Migrate %d: %v", i+1, err)
		}
	}
	assertVersionRows(t, db, s.versionTable(), "(6, false)")
}

// A complete database without a version table is recorded at this release;
// applying 000002 to it instead would fail on its duplicate columns.
func TestMigrate_RecordsCompleteUnversionedDatabase(t *testing.T) {
	t.Parallel()

	s, db := newVersionedSQLite(t)
	execAll(t, db, s.Schema())
	before := sqliteSchemaShape(t, db)
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	assertShape(t, "Migrate changed the adapter's tables", excludeTable(sqliteSchemaShape(t, db), s.versionTable()), before)
	assertVersionRows(t, db, s.versionTable(), "(6, false)")
}

// A partial database without a version table is refused unchanged. The
// estimate reads missing columns and tables only, so a database at 000002
// estimates as 000004: 000003 adds indexes alone.
func TestMigrate_RefusesPartialUnversionedDatabase(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		through int
		want    string
	}{
		{4, "INSERT INTO oidc_schema_migrations (version, dirty) VALUES (4, false)"},
		{2, "INSERT INTO oidc_schema_migrations (version, dirty) VALUES (4, false)"},
	} {
		t.Run(fmt.Sprintf("through_%d", tc.through), func(t *testing.T) {
			t.Parallel()

			s, db := newVersionedSQLite(t)
			applyMigrationsThrough(t, s, db, tc.through)
			before := sqliteSchemaShape(t, db)
			err := s.Migrate(t.Context())
			if err == nil {
				t.Fatal("Migrate accepted a partial database without a version table")
			}
			for _, want := range []string{
				"oidcsql: Migrate changed nothing: the database has the adapter's tables but no version table oidc_schema_migrations",
				"schema for oidc_ssf_streams is missing",
				tc.want,
			} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("Migrate error = %v\nwant it to contain %q", err, want)
				}
			}
			assertShape(t, "Migrate changed a database it refused", sqliteSchemaShape(t, db), before)
			if tableExists(t, db, s.versionTable()) {
				t.Error("Migrate created the version table before refusing")
			}
		})
	}
}

func TestMigrate_RefusesDirtyVersion(t *testing.T) {
	t.Parallel()

	s, db := newVersionedSQLite(t)
	applyMigrationsThrough(t, s, db, 4)
	recordVersion(t, db, s.versionTable(), 4, true)
	before := sqliteSchemaShape(t, db)
	err := s.Migrate(t.Context())
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
	assertShape(t, "Migrate changed a dirty database", sqliteSchemaShape(t, db), before)
	assertVersionRows(t, db, s.versionTable(), "(4, true)")
}

// A newer version applies nothing and returns the schema check: 000001 would
// recreate the dropped table with CREATE TABLE IF NOT EXISTS.
func TestMigrate_NewerVersionAppliesNothing(t *testing.T) {
	t.Parallel()

	s, db := newVersionedSQLite(t)
	applyMigrationsThrough(t, s, db, len(migrationStems()))
	recordVersion(t, db, s.versionTable(), 99, false)
	execAll(t, db, "DROP TABLE oidc_op_metadata")
	err := s.Migrate(t.Context())
	if err == nil || !strings.Contains(err.Error(), "schema for oidc_op_metadata is missing") {
		t.Fatalf("Migrate error = %v, want the missing oidc_op_metadata reported", err)
	}
	if tableExists(t, db, "oidc_op_metadata") {
		t.Error("Migrate applied a migration under a newer version")
	}
	assertVersionRows(t, db, s.versionTable(), "(99, false)")
}

func TestMigrate_VersionTableHasGolangMigrateColumns(t *testing.T) {
	t.Parallel()

	s, db := newVersionedSQLite(t)
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	collect := func(query string, args ...any) []string {
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
	const table = "oidc_schema_migrations"
	if got, want := collect(`SELECT name || ' ' || type || ' pk=' || pk FROM pragma_table_info(?) ORDER BY cid`, table),
		[]string{"version uint64 pk=0", "dirty bool pk=0"}; !slices.Equal(got, want) {
		t.Errorf("%s columns = %v, want %v", table, got, want)
	}
	if got, want := collect(`SELECT name || ' unique=' || "unique" FROM pragma_index_list(?)`, table),
		[]string{table + "_version_unique unique=1"}; !slices.Equal(got, want) {
		t.Errorf("%s indexes = %v, want %v", table, got, want)
	}
	if got, want := collect(`SELECT name FROM pragma_index_info(?)`, table+"_version_unique"), []string{"version"}; !slices.Equal(got, want) {
		t.Errorf("%s_version_unique columns = %v, want %v", table, got, want)
	}
}

// Two stores on separate pools migrate the same file at once; BEGIN IMMEDIATE
// and the per-file version re-read let both succeed with one row.
func TestMigrate_ConcurrentCallsAgree(t *testing.T) {
	t.Parallel()

	dsn := "file:" + t.TempDir() + "/oidc.db?_pragma=busy_timeout(5000)"
	stores := make([]*Store, 2)
	dbs := make([]*databasesql.DB, 0, len(stores))
	for i := range stores {
		db, err := databasesql.Open("sqlite", dsn)
		if err != nil {
			t.Fatalf("sql.Open: %v", err)
		}
		t.Cleanup(func() { _ = db.Close() })
		dbs = append(dbs, db)
		if stores[i], err = New(db, SQLite()); err != nil {
			t.Fatalf("New: %v", err)
		}
	}
	errs := make([]error, len(stores))
	var wg sync.WaitGroup
	for i, s := range stores {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.Migrate(t.Context())
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("Migrate %d: %v", i, err)
		}
	}
	assertVersionRows(t, dbs[0], "oidc_schema_migrations", "(6, false)")
	assertShape(t, "concurrent Migrate calls do not reach the chain's schema",
		excludeTable(sqliteSchemaShape(t, dbs[0]), "oidc_schema_migrations"), chainShape(t, stores[0]))
}

func TestMigrate_VersionTableFollowsPrefix(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		opts  []Option
		table string
	}{
		{"prefix", []Option{WithTablePrefix("acme_")}, "acme_schema_migrations"},
		{"naming", []Option{WithNaming(map[string]string{"clients": "partner_clients"})}, "oidc_schema_migrations"},
		{"naming of the version table", []Option{WithNaming(map[string]string{"schema_migrations": "partner_versions"})}, "partner_versions"},
		{"naming over prefix", []Option{WithTablePrefix("acme_"), WithNaming(map[string]string{"schema_migrations": "partner_versions"})}, "partner_versions"},
		{"empty prefix with a named version table", []Option{WithTablePrefix(""), WithNaming(map[string]string{"schema_migrations": "partner_versions"})}, "partner_versions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s, db := newVersionedSQLite(t, tc.opts...)
			if err := s.Migrate(t.Context()); err != nil {
				t.Fatalf("Migrate: %v", err)
			}
			assertVersionRows(t, db, tc.table, "(6, false)")
			var n int
			if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND (name LIKE '%schema\_migrations' ESCAPE '\' OR name LIKE '%versions')`).Scan(&n); err != nil {
				t.Fatalf("count version tables: %v", err)
			}
			if n != 1 {
				t.Errorf("%d version tables, want only %s", n, tc.table)
			}
		})
	}
}

// Migrate keeps every statement on the one connection it holds: a pool of one
// would otherwise block, and an in-memory database would be another database.
func TestMigrate_SingleConnectionPools(t *testing.T) {
	t.Parallel()

	for name, dsn := range map[string]func(t *testing.T) string{
		"memory": func(*testing.T) string { return ":memory:" },
		"file":   func(t *testing.T) string { return "file:" + t.TempDir() + "/oidc.db" },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			db, err := databasesql.Open("sqlite", dsn(t))
			if err != nil {
				t.Fatalf("sql.Open: %v", err)
			}
			t.Cleanup(func() { _ = db.Close() })
			db.SetMaxOpenConns(1)
			s, err := New(db, SQLite())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
			defer cancel()
			if err := s.Migrate(ctx); err != nil {
				t.Fatalf("Migrate: %v", err)
			}
			if err := s.ValidateSchema(ctx); err != nil {
				t.Fatalf("ValidateSchema after Migrate: %v", err)
			}
			assertVersionRows(t, db, s.versionTable(), "(6, false)")
		})
	}
}

// TestMigrate_Pairwise covers every pair of initial state, prefix and an
// unrelated application table "users" sharing the database.
func TestMigrate_Pairwise(t *testing.T) {
	t.Parallel()

	const (
		empty              = "empty"
		recordedK3         = "recorded_k3"
		completeUnrecorded = "complete_unrecorded"
		partialUnrecorded  = "partial_unrecorded"
		dirty              = "dirty"
		newer              = "newer"
	)
	rows := []struct {
		initial string
		prefix  string
		app     bool
	}{
		{partialUnrecorded, "", true},
		{partialUnrecorded, "acme_", false},
		{newer, "acme_", true},
		{completeUnrecorded, "", false},
		{completeUnrecorded, "acme_", true},
		{dirty, "acme_", false},
		{recordedK3, "", true},
		{dirty, "", true},
		{newer, "", false},
		{empty, "acme_", true},
		{recordedK3, "acme_", false},
		{empty, "", true},
		{empty, "", false},
	}
	for _, row := range rows {
		prefixLabel := "default"
		var opts []Option
		if row.prefix != "" {
			prefixLabel = row.prefix
			opts = append(opts, WithTablePrefix(row.prefix))
		}
		t.Run(fmt.Sprintf("%s/%s/app=%t", row.initial, prefixLabel, row.app), func(t *testing.T) {
			t.Parallel()

			s, db := newVersionedSQLite(t, opts...)
			vt := s.versionTable()
			if row.app {
				execAll(t, db,
					"CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT)",
					"INSERT INTO users (email) VALUES ('a@example.com')")
			}
			switch row.initial {
			case recordedK3:
				applyMigrationsThrough(t, s, db, 3)
				recordVersion(t, db, vt, 3, false)
			case completeUnrecorded:
				execAll(t, db, s.Schema())
			case partialUnrecorded:
				applyMigrationsThrough(t, s, db, 4)
			case dirty:
				applyMigrationsThrough(t, s, db, 4)
				recordVersion(t, db, vt, 4, true)
			case newer:
				applyMigrationsThrough(t, s, db, len(migrationStems()))
				recordVersion(t, db, vt, 99, false)
			}
			before := sqliteSchemaShape(t, db)

			err := s.Migrate(t.Context())

			switch row.initial {
			case partialUnrecorded, dirty:
				want := "INSERT INTO " + vt + " (version, dirty) VALUES (4, false)"
				wantRows := []string(nil)
				if row.initial == dirty {
					want = "version table " + vt + " is dirty at version 4"
					wantRows = []string{"(4, true)"}
				}
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("Migrate error = %v, want it to contain %q", err, want)
				}
				assertShape(t, "Migrate changed a database it refused", sqliteSchemaShape(t, db), before)
				assertVersionRows(t, db, vt, wantRows...)
			default:
				if err != nil {
					t.Fatalf("Migrate: %v", err)
				}
				assertShape(t, "Migrate does not reach the chain's schema",
					excludeTable(excludeTable(sqliteSchemaShape(t, db), vt), "users"), chainShape(t, s))
				wantRow := "(6, false)"
				if row.initial == newer {
					wantRow = "(99, false)"
				}
				assertVersionRows(t, db, vt, wantRow)
			}

			if row.app {
				var columns string
				var n int
				if err := db.QueryRowContext(t.Context(), `SELECT group_concat(name, ',') FROM pragma_table_info('users')`).Scan(&columns); err != nil {
					t.Fatalf("read users columns: %v", err)
				}
				if err := db.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
					t.Fatalf("count users: %v", err)
				}
				if columns != "id,email" || n != 1 {
					t.Errorf("users changed: columns %q, %d rows", columns, n)
				}
			}
		})
	}
}
