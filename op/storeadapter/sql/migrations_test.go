//nolint:testpackage // tests reference the unexported release history, statement splitter and embedded schema FS.
package oidcsql

import (
	"context"
	databasesql "database/sql"
	"io/fs"
	"maps"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	_ "modernc.org/sqlite"
)

// migrationStems lists every migration file stem in apply order.
func migrationStems() []string {
	out := make([]string, 0, 1+len(schemaReleases))
	out = append(out, baselineMigration)
	for _, r := range schemaReleases {
		out = append(out, r.migration)
	}
	return out
}

// readMigration returns one shipped migration file with the default names.
func readMigration(t *testing.T, dialect, stem string) []byte {
	t.Helper()

	raw, err := schemaFS.ReadFile("schema/migrations/" + dialect + "/" + stem + ".up.sql")
	if err != nil {
		t.Fatalf("read %s migration %s: %v", dialect, stem, err)
	}
	return raw
}

func TestMigrations_EveryReleaseHasEveryDialect(t *testing.T) {
	t.Parallel()

	for i, r := range schemaReleases {
		if !strings.HasSuffix(r.migration, "_"+r.version) {
			t.Errorf("schemaReleases[%d] %s names migration %q, which is not for that version", i, r.version, r.migration)
		}
	}
	want := migrationStems()
	if !slices.IsSorted(want) {
		t.Errorf("migration stems %v do not sort in release order", want)
	}

	dirs, err := fs.ReadDir(schemaFS, "schema/migrations")
	if err != nil {
		t.Fatalf("read migrations directory: %v", err)
	}
	got := make([]string, 0, len(dirs))
	for _, d := range dirs {
		got = append(got, d.Name())
	}
	if dialects := slices.Sorted(maps.Keys(allDialects())); !slices.Equal(got, dialects) {
		t.Errorf("migration directories %v, want one per dialect %v", got, dialects)
	}

	for name := range allDialects() {
		entries, err := fs.ReadDir(schemaFS, "schema/migrations/"+name)
		if err != nil {
			t.Fatalf("read %s migrations: %v", name, err)
		}
		var files []string
		for _, e := range entries {
			files = append(files, e.Name())
		}
		wantFiles := make([]string, len(want))
		for i, stem := range want {
			wantFiles[i] = stem + ".up.sql"
		}
		if !slices.Equal(files, wantFiles) {
			t.Errorf("%s migrations are %v, want %v", name, files, wantFiles)
		}
		for _, f := range files {
			if strings.Contains(string(readMigration(t, name, strings.TrimSuffix(f, ".up.sql"))), "/*") {
				t.Errorf("%s/%s has a block comment; migration files use -- line comments only", name, f)
			}
		}
	}
}

// openMigrationSQLite returns an empty SQLite database private to the test.
func openMigrationSQLite(t *testing.T) *databasesql.DB {
	t.Helper()

	db, err := databasesql.Open("sqlite", "file:"+t.TempDir()+"/oidc.db?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// sqliteSchemaShape describes every table, column and index of a SQLite
// database as sorted lines, from the engine's own catalog.
func sqliteSchemaShape(t *testing.T, db *databasesql.DB) []string {
	t.Helper()

	ctx := t.Context()
	var out []string
	collect := func(query string, args ...any) []string {
		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			t.Fatalf("query %q: %v", query, err)
		}
		defer func() { _ = rows.Close() }()
		var lines []string
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatalf("scan: %v", err)
			}
			lines = append(lines, s)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("rows: %v", err)
		}
		return lines
	}
	tables := collect(`SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'`)
	for _, table := range tables {
		out = append(out, "table "+table)
		out = append(out, collect(`SELECT ? || '.' || name || ' ' || type || ' notnull=' || "notnull" || ' default=' || IFNULL(dflt_value, 'NULL') || ' pk=' || pk
			FROM pragma_table_info(?)`, table, table)...)
		for _, index := range collect(`SELECT name || ' unique=' || "unique" FROM pragma_index_list(?)`, table) {
			name := strings.Fields(index)[0]
			cols := collect(`SELECT name FROM pragma_index_info(?) ORDER BY seqno`, name)
			out = append(out, "index "+table+"."+index+" ("+strings.Join(cols, ",")+")")
		}
	}
	slices.Sort(out)
	return out
}

// applyMigrationChain runs every file of fsys in order, either split into
// statements the way Migrate splits the schema or as one Exec per file the
// way a migration tool sends it.
func applyMigrationChain(t *testing.T, db *databasesql.DB, fsys fs.FS, split bool) {
	t.Helper()

	for _, stem := range migrationStems() {
		raw, err := fs.ReadFile(fsys, stem+".up.sql")
		if err != nil {
			t.Fatalf("read %s: %v", stem, err)
		}
		if !split {
			if _, err := db.ExecContext(t.Context(), string(raw)); err != nil {
				t.Fatalf("apply %s: %v", stem, err)
			}
			continue
		}
		for _, stmt := range splitStatements(string(raw)) {
			if _, err := db.ExecContext(t.Context(), stmt); err != nil {
				t.Fatalf("apply %s statement %q: %v", stem, stmt, err)
			}
		}
	}
}

func TestMigrations_ChainEqualsMigrateSQLite(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	fresh := openMigrationSQLite(t)
	s, err := New(fresh, SQLite())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	want := sqliteSchemaShape(t, fresh)

	tableNames := defaultNames().all()
	catalog := make([]string, 0, len(tableNames))
	for _, table := range tableNames {
		catalog = append(catalog, "table "+table)
	}
	slices.Sort(catalog)
	var tables []string
	for _, line := range want {
		if strings.HasPrefix(line, "table ") {
			tables = append(tables, line)
		}
	}
	if !slices.Equal(tables, catalog) {
		t.Fatalf("Migrate created %v, the table catalog names %v", tables, catalog)
	}

	for mode, split := range map[string]bool{"split": true, "raw": false} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			db := openMigrationSQLite(t)
			applyMigrationChain(t, db, s.Migrations(), split)
			got := sqliteSchemaShape(t, db)
			if !slices.Equal(got, want) {
				t.Errorf("the migration chain does not reach the Migrate schema\nmissing: %v\nunexpected: %v",
					setDifference(want, got), setDifference(got, want))
			}
			chained, err := New(db, SQLite())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := chained.ValidateSchema(ctx); err != nil {
				t.Errorf("ValidateSchema after the chain: %v", err)
			}
		})
	}
}

// setDifference returns the entries of a that b lacks.
func setDifference(a, b []string) []string {
	var out []string
	for _, s := range a {
		if !slices.Contains(b, s) {
			out = append(out, s)
		}
	}
	return out
}

func TestMigrations_FSAppliesNaming(t *testing.T) {
	t.Parallel()

	db := openMigrationSQLite(t)
	s, err := New(db, SQLite(), WithNaming(map[string]string{
		"clients":    "acme_clients",
		"ssf_events": "acme_ssf_events",
	}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fsys := s.Migrations()

	stems := migrationStems()
	files := make([]string, 0, len(stems))
	for _, stem := range stems {
		files = append(files, stem+".up.sql")
	}
	if err := fstest.TestFS(fsys, files...); err != nil {
		t.Fatalf("Migrations is not a consistent fs.FS: %v", err)
	}

	for name, want := range map[string]string{
		baselineMigration + ".up.sql": "CREATE TABLE IF NOT EXISTS acme_clients",
		"000006_v1.5.0.up.sql":        "CREATE TABLE IF NOT EXISTS acme_ssf_events",
	} {
		got, err := fs.ReadFile(fsys, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !strings.Contains(string(got), want) {
			t.Errorf("%s lacks %q", name, want)
		}
		for _, old := range []string{"oidc_clients", "oidc_ssf_events"} {
			if strings.Contains(string(got), old) {
				t.Errorf("%s still names %s", name, old)
			}
		}
	}

	applyMigrationChain(t, db, fsys, false)
	if err := s.ValidateSchema(t.Context()); err != nil {
		t.Errorf("ValidateSchema after the renamed chain: %v", err)
	}
}
