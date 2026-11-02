//nolint:testpackage // tests use the unexported name map and error helpers.
package oidcsql

import (
	"strings"
	"testing"
)

// A prefix whose tables fit in 63 bytes can still push the index names the
// DDL derives from them past the limit.
func TestNew_LongPrefixRejectedByIndexNames(t *testing.T) {
	t.Parallel()

	prefix := strings.Repeat("p", 34) + "_"
	dialects := map[string]Dialect{"sqlite": SQLite(), "mysql": MySQL(), "postgres": Postgres()}
	for name, d := range dialects {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if err := namesWithPrefix(prefix).validateAll(); err != nil {
				t.Fatalf("the prefix must pass the table-name checks: %v", err)
			}
			_, err := New(openMigrationSQLite(t), d, WithTablePrefix(prefix))
			if err == nil {
				t.Fatal("New accepted a prefix that makes an index name longer than 63 bytes")
			}
			for _, want := range []string{"index \"idx_" + prefix, "exceeds 63 bytes", "of table \"" + prefix} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
		})
	}
}

func TestNew_DefaultAndShortPrefixIndexNamesAccepted(t *testing.T) {
	t.Parallel()

	for _, opts := range [][]Option{nil, {WithTablePrefix("sso_")}, {WithTablePrefix("")}} {
		for _, d := range []Dialect{SQLite(), MySQL(), Postgres()} {
			if _, err := New(openMigrationSQLite(t), d, opts...); err != nil {
				t.Errorf("%s: New: %v", d.name, err)
			}
		}
	}
}

func TestParseDDLIndexNames_BothShapes(t *testing.T) {
	t.Parallel()

	got := parseDDLIndexNames("CREATE UNIQUE INDEX IF NOT EXISTS idx_a ON t1 (x);\n" +
		"CREATE TABLE t2 (\n  id INT,\n  UNIQUE KEY uq_b (id),\n  INDEX idx_c (id)\n);")
	want := []declaredIndex{{"idx_a", "t1"}, {"uq_b", "t2"}, {"idx_c", "t2"}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("index %d = %v, want %v", i, got[i], want[i])
		}
	}
}

// Renamed tables point at Store.Schema(); the default names keep the file.
func TestMissingIndexHint_NamesStoreSchemaForRenamedTables(t *testing.T) {
	t.Parallel()

	db := openMigrationSQLite(t)
	s, err := New(db, SQLite(), WithTablePrefix("sso_"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	execAll(t, db, "DROP INDEX idx_sso_refresh_tokens_expires")
	err = s.ValidateSchema(t.Context())
	if err == nil {
		t.Fatal("ValidateSchema passed without the index")
	}
	if !strings.Contains(err.Error(), "create it from Store.Schema()") || strings.Contains(err.Error(), "v1.sql") {
		t.Errorf("hint must point at Store.Schema() and not v1.sql: %v", err)
	}
}

func TestMissingTableError_NamesWhereItLooked(t *testing.T) {
	t.Parallel()

	got := missingTableError("oidc_users", "in search_path schemas (app, oidc)", "").Error()
	if want := "oidcsql: schema for oidc_users is missing in search_path schemas (app, oidc)"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := missingTableError("oidc_users", "", "").Error(); got != "oidcsql: schema for oidc_users is missing" {
		t.Errorf("empty scope: got %q", got)
	}
}
