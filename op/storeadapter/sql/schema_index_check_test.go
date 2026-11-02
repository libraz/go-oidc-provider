//nolint:testpackage // tests use the unexported migration helpers and release history.
package oidcsql

import (
	databasesql "database/sql"
	"io/fs"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// newMigratedSQLite returns a store over a SQLite database that Migrate has
// brought to the current schema.
func newMigratedSQLite(t *testing.T) (*Store, *databasesql.DB) {
	t.Helper()

	db := openMigrationSQLite(t)
	s, err := New(db, SQLite())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate on a fresh database must pass the index check: %v", err)
	}
	return s, db
}

func execAll(t *testing.T, db *databasesql.DB, stmts ...string) {
	t.Helper()

	for _, stmt := range stmts {
		if _, err := db.ExecContext(t.Context(), stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
}

func TestValidateSchema_MissingIndexFailsFullAndScopedChecks(t *testing.T) {
	t.Parallel()

	s, db := newMigratedSQLite(t)
	execAll(t, db, "DROP INDEX idx_oidc_refresh_tokens_expires")
	scoped, ok := s.RefreshTokens().(store.SchemaValidator)
	if !ok {
		t.Fatal("RefreshTokens is not a SchemaValidator")
	}
	const want = "oidcsql: oidc_refresh_tokens has no index on expires_at; create it from schema/sqlite/v1.sql"
	for name, err := range map[string]error{"full": s.ValidateSchema(t.Context()), "scoped": scoped.ValidateSchema(t.Context())} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s check error = %v, want it to contain %q", name, err, want)
		}
	}
	if err := s.ValidateSchema(t.Context()); strings.Contains(err.Error(), "migrate force") {
		t.Errorf("a missing index alone must not produce a migrate force hint: %v", err)
	}
}

// The check compares leading columns, never index names.
func TestValidateSchema_IndexUnderAnotherNamePasses(t *testing.T) {
	t.Parallel()

	s, db := newMigratedSQLite(t)
	execAll(t, db,
		"DROP INDEX idx_oidc_refresh_tokens_expires",
		"CREATE INDEX embedder_refresh_sweep ON oidc_refresh_tokens(expires_at, grant_id)",
	)
	if err := s.ValidateSchema(t.Context()); err != nil {
		t.Fatalf("ValidateSchema with an equivalent index under another name: %v", err)
	}
}

func TestValidateSchema_MissingIndexSkipsMissingTable(t *testing.T) {
	t.Parallel()

	s, db := newMigratedSQLite(t)
	execAll(t, db, "DROP TABLE oidc_consumed_jtis")
	err := s.ValidateSchema(t.Context())
	if err == nil || strings.Contains(err.Error(), "has no index") {
		t.Fatalf("a missing table must be reported once and not as a missing index: %v", err)
	}
}

// applyMigrationsThrough applies the first n migration files, as a database
// created by the release that wrote the nth would have them.
func applyMigrationsThrough(t *testing.T, s *Store, db *databasesql.DB, n int) {
	t.Helper()

	for _, stem := range migrationStems()[:n] {
		raw, err := fs.ReadFile(s.Migrations(), stem+".up.sql")
		if err != nil {
			t.Fatalf("read %s: %v", stem, err)
		}
		execAll(t, db, string(raw))
	}
}

func TestValidateSchema_AppliedReleaseHint(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		through int
		want    string
	}{
		{"v1.0.0", 1, `the schema matches release v1.0.0 (migration 000001); a database golang-migrate does not track yet records that with "migrate force 1" before "migrate up"`},
		{"v1.3.0", 4, `the schema matches release v1.3.0 (migration 000004); a database golang-migrate does not track yet records that with "migrate force 4" before "migrate up"`},
		{"empty", 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			db := openMigrationSQLite(t)
			s, err := New(db, SQLite())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			applyMigrationsThrough(t, s, db, tc.through)
			err = s.ValidateSchema(t.Context())
			if err == nil {
				t.Fatal("ValidateSchema passed on an older schema")
			}
			if tc.want == "" {
				if strings.Contains(err.Error(), "migrate force") {
					t.Errorf("an empty database has no applied release to record: %v", err)
				}
				return
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not contain %q", err, tc.want)
			}
		})
	}
}

// A gap from the first release means no release is known to be applied.
func TestValidateSchema_NoReleaseHintWhenBaselineIsMissing(t *testing.T) {
	t.Parallel()

	s, db := newMigratedSQLite(t)
	execAll(t, db,
		"DROP TABLE oidc_authn_lockouts",
		"CREATE TABLE oidc_authn_lockouts (subject TEXT PRIMARY KEY, failed_count INTEGER NOT NULL)",
		"ALTER TABLE oidc_totp_secrets DROP COLUMN row_version",
	)
	err := s.ValidateSchema(t.Context())
	if err == nil {
		t.Fatal("ValidateSchema passed with columns missing")
	}
	if strings.Contains(err.Error(), "migrate force") {
		t.Errorf("a missing v1.0.0 column must suppress the migrate force hint: %v", err)
	}
}
