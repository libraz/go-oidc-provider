//nolint:testpackage // tests reference unexported name resolution and migration helpers.
package oidcsql

import (
	"io/fs"
	"strings"
	"testing"
)

func TestWithTablePrefix_MigratesValidatesAndRoundTrips(t *testing.T) {
	t.Parallel()

	db := openMigrationSQLite(t)
	s, err := New(db, SQLite(), WithTablePrefix("acme_"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := t.Context()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := s.ValidateSchema(ctx); err != nil {
		t.Fatalf("ValidateSchema: %v", err)
	}

	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name LIKE 'oidc\_%' ESCAPE '\'`).Scan(&n); err != nil {
		t.Fatalf("count default-named tables: %v", err)
	}
	if n != 0 {
		t.Errorf("%d tables still carry the default prefix", n)
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE name = 'idx_acme_grants_client'`).Scan(&n); err != nil {
		t.Fatalf("count index: %v", err)
	}
	if n != 1 {
		t.Errorf("index idx_acme_grants_client not created, count %d", n)
	}

	meta := s.Metadata()
	if err := meta.Set(ctx, "k", "v"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got, err := meta.Get(ctx, "k"); err != nil || got != "v" {
		t.Fatalf("Get = %q, %v; want v", got, err)
	}
	if _, err := s.GC(ctx, s.clock.Now()); err != nil {
		t.Errorf("GC: %v", err)
	}
}

func TestWithTablePrefix_MigrationsUsePrefixedNames(t *testing.T) {
	t.Parallel()

	db := openMigrationSQLite(t)
	s, err := New(db, SQLite(), WithTablePrefix("acme_"), WithNaming(map[string]string{"clients": "partner_clients"}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fsys := s.Migrations()
	for name, want := range map[string]string{
		baselineMigration + ".up.sql": "CREATE TABLE IF NOT EXISTS acme_sessions",
		"000006_v1.5.0.up.sql":        "CREATE TABLE IF NOT EXISTS acme_ssf_events",
	} {
		got, err := fs.ReadFile(fsys, name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		if !strings.Contains(string(got), want) {
			t.Errorf("%s lacks %q", name, want)
		}
		if strings.Contains(string(got), "oidc_") {
			t.Errorf("%s still names an oidc_ table", name)
		}
	}
	if got := s.Schema(); !strings.Contains(got, "partner_clients") || strings.Contains(got, "acme_clients") {
		t.Errorf("WithNaming must override the prefixed name outright")
	}

	applyMigrationChain(t, db, fsys, false)
	if err := s.ValidateSchema(t.Context()); err != nil {
		t.Errorf("ValidateSchema after the prefixed chain: %v", err)
	}
}

func TestWithTablePrefix_EmptyPrefixDropsIt(t *testing.T) {
	t.Parallel()

	db := openMigrationSQLite(t)
	s, err := New(db, SQLite(), WithTablePrefix(""))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.names.clients != "clients" || s.names.authCodes != "authorization_codes" {
		t.Errorf("empty prefix resolved to %q, %q", s.names.clients, s.names.authCodes)
	}
	applyMigrationChain(t, db, s.Migrations(), false)
	if err := s.ValidateSchema(t.Context()); err != nil {
		t.Fatalf("ValidateSchema after the unprefixed chain: %v", err)
	}
}

// Under the empty prefix the version table would be golang-migrate's default
// table, so Migrate refuses before touching the database.
func TestMigrate_RefusesEmptyPrefix(t *testing.T) {
	t.Parallel()

	db := openMigrationSQLite(t)
	ctx := t.Context()
	s, err := New(db, SQLite(), WithTablePrefix(""))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = s.Migrate(ctx)
	const want = `oidcsql: Migrate needs a table prefix: with WithTablePrefix("") the version table would be "schema_migrations", ` +
		`golang-migrate's default table; apply Store.Migrations() with your migration tool instead`
	if err == nil || err.Error() != want {
		t.Fatalf("Migrate error = %v, want %q", err, want)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master`).Scan(&n); err != nil {
		t.Fatalf("count schema objects: %v", err)
	}
	if n != 0 {
		t.Errorf("Migrate created %d object(s) before refusing", n)
	}
}

func TestWithTablePrefix_RejectsInvalid(t *testing.T) {
	t.Parallel()

	for name, prefix := range map[string]string{
		"semicolon":     "x;DROP TABLE y;--",
		"space":         "my app_",
		"dot":           "app.",
		"leading digit": "1app_",
		"quote":         `a"b`,
		"too long":      strings.Repeat("a", 40),
	} {
		if _, err := New(openMigrationSQLite(t), SQLite(), WithTablePrefix(prefix)); err == nil {
			t.Errorf("%s: New accepted prefix %q", name, prefix)
		}
	}
}

// Migrate must refuse before executing any statement when a name the adapter
// would use is an application table, leaving that table and its indexes alone
// and creating nothing, the version table included.
func TestMigrate_RefusesForeignTableWithoutChangingIt(t *testing.T) {
	t.Parallel()

	db := openMigrationSQLite(t)
	ctx := t.Context()
	execAll(t, db, "CREATE TABLE acme_users (id INTEGER PRIMARY KEY, email TEXT)")
	s, err := New(db, SQLite(), WithTablePrefix("acme_"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	err = s.Migrate(ctx)
	const want = "oidcsql: Migrate changed nothing: table acme_users exists but is not the adapter's table (missing baseline columns: "
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("Migrate error = %v, want it to contain %q", err, want)
	}
	var n int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE name <> 'acme_users'`).Scan(&n); err != nil {
		t.Fatalf("count schema objects: %v", err)
	}
	if n != 0 {
		t.Errorf("Migrate created %d object(s) before refusing", n)
	}
}
