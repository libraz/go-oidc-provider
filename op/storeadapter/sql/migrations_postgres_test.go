//go:build testcontainers

package oidcsql_test

import (
	databasesql "database/sql"
	"io/fs"
	"slices"
	"testing"

	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// postgresSchemaShape describes every table, column and index of the
// current schema as sorted lines, from the engine's own catalog. The table
// named exclude, with its columns and indexes, is left out.
func postgresSchemaShape(t *testing.T, db *databasesql.DB, exclude string) []string {
	t.Helper()

	var out []string
	for _, query := range []string{
		`SELECT 'column ' || table_name || '.' || column_name || ' ' || data_type || ' nullable=' || is_nullable || ' default=' || COALESCE(column_default, 'NULL')
			FROM information_schema.columns WHERE table_schema = current_schema() AND table_name <> $1`,
		`SELECT 'index ' || indexdef FROM pg_indexes WHERE schemaname = current_schema() AND tablename <> $1`,
	} {
		rows, err := db.QueryContext(t.Context(), query, exclude)
		if err != nil {
			t.Fatalf("query catalog: %v", err)
		}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				t.Fatalf("scan: %v", err)
			}
			out = append(out, s)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("rows: %v", err)
		}
		_ = rows.Close()
	}
	slices.Sort(out)
	return out
}

// TestMigrations_ChainEqualsMigratePostgres applies every migration file,
// each as one Exec the way golang-migrate sends it, to an empty database
// and requires the result to match a database built by Migrate, apart from
// the version table only Migrate creates.
func TestMigrations_ChainEqualsMigratePostgres(t *testing.T) {
	t.Parallel()

	openDB := newPostgresDBFactory(t)

	freshDB := openDB(t)
	fresh, err := oidcsql.New(freshDB, oidcsql.Postgres())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := fresh.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	db := openDB(t)
	chained, err := oidcsql.New(db, oidcsql.Postgres())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fsys := chained.Migrations()
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	for _, e := range entries {
		raw, err := fs.ReadFile(fsys, e.Name())
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if _, err := db.ExecContext(t.Context(), string(raw)); err != nil {
			t.Fatalf("apply %s: %v", e.Name(), err)
		}
	}
	if err := chained.ValidateSchema(t.Context()); err != nil {
		t.Errorf("ValidateSchema after the chain: %v", err)
	}

	want, got := postgresSchemaShape(t, freshDB, "oidc_schema_migrations"), postgresSchemaShape(t, db, "oidc_schema_migrations")
	if !slices.Equal(got, want) {
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
		t.Errorf("the migration chain does not reach the Migrate schema\nmissing: %v\nunexpected: %v", missing, extra)
	}
}
