//go:build testcontainers

//nolint:testpackage // reuses the unexported MIGRATIONS.md section parser and the embedded schema FS.
package oidcsql

import (
	"context"
	databasesql "database/sql"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	mysqlmod "github.com/testcontainers/testcontainers-go/modules/mysql"
)

// The static check in schema_migrations_test.go asks whether MIGRATIONS.md
// names each index. That cannot tell whether the statements work: a wrong
// column, a table renamed since, or an ALTER that MySQL rejects all read the
// same to a name matcher. This file applies the document instead of parsing
// it, and compares the result against a fresh install of the current schema.
//
// MySQL is the engine that needs it. SQLite and PostgreSQL declare indexes as
// standalone CREATE INDEX IF NOT EXISTS statements that a later Store.Migrate
// re-applies, so an existing database converges on its own. MySQL declares
// them inline in CREATE TABLE, and CREATE TABLE IF NOT EXISTS does nothing to
// a table that exists — the document is the entire upgrade path, and a defect
// in it is invisible until a query plans badly in production.

// mysqlMigrationImage pins the same engine version the contract harness uses.
const mysqlMigrationImage = "mysql:8.4"

// applyMySQLBaselineAndMigrations builds the "upgraded" database: the schema
// as v1.0.0 shipped it, then exactly the statements an operator reading
// MIGRATIONS.md would run.
func applyMySQLBaselineAndMigrations(t *testing.T, db *databasesql.DB) {
	t.Helper()

	baseline, err := testdataFS.ReadFile("testdata/mysql_v1.0.0.sql")
	if err != nil {
		t.Fatalf("read frozen v1.0.0 MySQL schema: %v", err)
	}
	if _, err := db.ExecContext(t.Context(), string(baseline)); err != nil {
		t.Fatalf("apply v1.0.0 schema: %v", err)
	}
	for _, stmt := range mysqlMigrationStatements(t) {
		if _, err := db.ExecContext(t.Context(), stmt); err != nil {
			t.Fatalf("apply MIGRATIONS.md statement %q: %v", stmt, err)
		}
	}
}

// mysqlMigrationStatements returns the statements inside the MySQL fenced
// block of MIGRATIONS.md, in document order.
func mysqlMigrationStatements(t *testing.T) []string {
	t.Helper()

	section := migrationsSection(t, migrationsDoc(t), "MySQL/MariaDB")
	fence := strings.Index(string(section), "```sql")
	if fence < 0 {
		t.Fatal("MySQL section of MIGRATIONS.md has no sql code fence")
	}
	body := string(section)[fence+len("```sql"):]
	if end := strings.Index(body, "```"); end >= 0 {
		body = body[:end]
	}
	var out []string
	for _, raw := range strings.Split(body, ";") {
		stmt := strings.TrimSpace(raw)
		if stmt == "" {
			continue
		}
		out = append(out, stmt)
	}
	if len(out) == 0 {
		t.Fatal("no statements parsed from the MySQL section; the document shape changed and this test stopped checking anything")
	}
	return out
}

// describeSchema reads the live index and column layout out of
// information_schema, which is the engine's own account of what the DDL
// produced rather than a re-reading of the DDL.
func describeSchema(t *testing.T, db *databasesql.DB) (indexes, columns []string) {
	t.Helper()

	indexes = queryStrings(t, db, `
		SELECT CONCAT(TABLE_NAME, '.', INDEX_NAME, '[', SEQ_IN_INDEX, ']=', COLUMN_NAME)
		FROM information_schema.STATISTICS
		WHERE TABLE_SCHEMA = DATABASE()`)
	columns = queryStrings(t, db, `
		SELECT CONCAT(TABLE_NAME, '.', COLUMN_NAME)
		FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE()`)
	return indexes, columns
}

func queryStrings(t *testing.T, db *databasesql.DB, query string) []string {
	t.Helper()

	rows, err := db.QueryContext(t.Context(), query)
	if err != nil {
		t.Fatalf("query information_schema: %v", err)
	}
	defer func() { _ = rows.Close() }()

	var out []string
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
	sort.Strings(out)
	return out
}

// diffSets reports entries present in want but missing from got, and vice
// versa.
func diffSets(want, got []string) (missing, extra []string) {
	inGot := make(map[string]bool, len(got))
	for _, g := range got {
		inGot[g] = true
	}
	inWant := make(map[string]bool, len(want))
	for _, w := range want {
		inWant[w] = true
		if !inGot[w] {
			missing = append(missing, w)
		}
	}
	for _, g := range got {
		if !inWant[g] {
			extra = append(extra, g)
		}
	}
	return missing, extra
}

// TestMySQL_MigrationsReachTheCurrentSchema is the acceptance the static
// check cannot give: a database created by v1.0.0 and upgraded only by
// MIGRATIONS.md has to end up with the same indexes and columns as a database
// created fresh from the current v1.sql. Anything the document forgets, spells
// wrong, or points at the wrong table shows up here as a difference.
func TestMySQL_MigrationsReachTheCurrentSchema(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	ctr, err := mysqlmod.Run(ctx, mysqlMigrationImage,
		mysqlmod.WithUsername("root"),
		mysqlmod.WithPassword("oidcpw"),
		mysqlmod.WithDatabase("oidc_admin"),
	)
	if err != nil {
		if os.Getenv("RELEASE_CONTRACT_REQUIRED") == "1" {
			t.Fatalf("mysql container required for release contract: %v", err)
		}
		t.Skipf("mysql container unavailable (Docker not running?): %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	adminDSN, err := ctr.ConnectionString(ctx, "parseTime=true", "multiStatements=true")
	if err != nil {
		t.Fatalf("ConnectionString: %v", err)
	}
	baseCfg, err := mysqldriver.ParseDSN(adminDSN)
	if err != nil {
		t.Fatalf("ParseDSN: %v", err)
	}
	admin, err := databasesql.Open("mysql", adminDSN)
	if err != nil {
		t.Fatalf("open admin: %v", err)
	}
	t.Cleanup(func() { _ = admin.Close() })

	openDB := func(name string) *databasesql.DB {
		if _, err := admin.ExecContext(ctx, "CREATE DATABASE `"+name+"`"); err != nil {
			t.Fatalf("CREATE DATABASE %s: %v", name, err)
		}
		cfg := *baseCfg
		cfg.DBName = name
		db, err := databasesql.Open("mysql", cfg.FormatDSN())
		if err != nil {
			t.Fatalf("open %s: %v", name, err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}

	upgraded := openDB("oidc_upgraded")
	applyMySQLBaselineAndMigrations(t, upgraded)

	fresh := openDB("oidc_fresh")
	store, err := New(fresh, MySQL())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate a fresh database: %v", err)
	}

	wantIndexes, wantColumns := describeSchema(t, fresh)
	gotIndexes, gotColumns := describeSchema(t, upgraded)

	if missing, extra := diffSets(wantIndexes, gotIndexes); len(missing) > 0 || len(extra) > 0 {
		t.Errorf("an upgraded database does not carry the current index set\n"+
			"missing (v1.sql has them, MIGRATIONS.md never creates them): %s\n"+
			"unexpected (MIGRATIONS.md creates them, v1.sql does not): %s",
			formatList(missing), formatList(extra))
	}
	if missing, extra := diffSets(wantColumns, gotColumns); len(missing) > 0 || len(extra) > 0 {
		t.Errorf("an upgraded database does not carry the current column set\n"+
			"missing: %s\nunexpected: %s", formatList(missing), formatList(extra))
	}
}

func formatList(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return fmt.Sprintf("%d entr(ies) %v", len(items), items)
}
