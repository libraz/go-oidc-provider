//go:build testcontainers

//nolint:testpackage // reuses the unexported release history and the embedded schema FS.
package oidcsql

import (
	"context"
	databasesql "database/sql"
	"fmt"
	"os"
	"sort"
	"testing"

	mysqldriver "github.com/go-sql-driver/mysql"
	mysqlmod "github.com/testcontainers/testcontainers-go/modules/mysql"
)

// The static check in schema_migrations_test.go asks whether the migration
// files name each index. That cannot tell whether the statements work: a
// wrong column, a table renamed since, or an ALTER that MySQL rejects all read
// the same to a name matcher. This file applies the chain instead of parsing
// it, and compares the result against a database built by Store.Migrate,
// which applies the same migration files and records the version.
//
// MySQL declares indexes inline in CREATE TABLE, so a defect in a migration
// file is invisible until a query plans badly in production. The version
// table only Migrate creates is left out of the comparison.

// mysqlMigrationImage pins the same engine version the contract harness uses.
const mysqlMigrationImage = "mysql:8.4"

// applyMySQLMigrationChain builds the "upgraded" database: every migration
// file from 000001 on, each sent as one multi-statement Exec the way
// golang-migrate sends it.
func applyMySQLMigrationChain(t *testing.T, db *databasesql.DB) {
	t.Helper()

	for _, stem := range migrationStems() {
		if _, err := db.ExecContext(t.Context(), string(readMigration(t, "mysql", stem))); err != nil {
			t.Fatalf("apply migration %s: %v", stem, err)
		}
	}
}

// describeSchema reads the live index, column and collation layout out of
// information_schema, which is the engine's own account of what the DDL
// produced rather than a re-reading of the DDL.
func describeSchema(t *testing.T, db *databasesql.DB) (indexes, columns []string) {
	t.Helper()

	indexes = queryStrings(t, db, `
		SELECT CONCAT(TABLE_NAME, '.', INDEX_NAME, '[', SEQ_IN_INDEX, ']=', COLUMN_NAME)
		FROM information_schema.STATISTICS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME <> 'oidc_schema_migrations'`)
	columns = queryStrings(t, db, `
		SELECT CONCAT(TABLE_NAME, '.', COLUMN_NAME, ' ', IFNULL(COLLATION_NAME, '-'))
		FROM information_schema.COLUMNS
		WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME <> 'oidc_schema_migrations'`)
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
// check cannot give: an empty database taken through the migration chain has
// to end up with the same indexes, columns and collations as a database
// created fresh from the current v1.sql. Anything a migration forgets, spells
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
	applyMySQLMigrationChain(t, upgraded)

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
			"missing (v1.sql has them, no migration creates them): %s\n"+
			"unexpected (a migration creates them, v1.sql does not): %s",
			formatList(missing), formatList(extra))
	}
	if missing, extra := diffSets(wantColumns, gotColumns); len(missing) > 0 || len(extra) > 0 {
		t.Errorf("an upgraded database does not carry the current columns and collations\n"+
			"missing: %s\nunexpected: %s", formatList(missing), formatList(extra))
	}
}

func formatList(items []string) string {
	if len(items) == 0 {
		return "(none)"
	}
	return fmt.Sprintf("%d entr(ies) %v", len(items), items)
}
