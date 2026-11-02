//go:build testcontainers

package oidcsql_test

import (
	"strings"
	"testing"

	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// TestPostgres_ValidateSchema_MissingIndex drops a sweep index and expects
// the check to name it; an index of the same leading column under another
// name passes.
func TestPostgres_ValidateSchema_MissingIndex(t *testing.T) {
	t.Parallel()
	db := newPostgresDBFactory(t)(t)
	s, err := oidcsql.New(db, oidcsql.Postgres())
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate on a fresh database must pass the index check: %v", err)
	}
	if _, err := db.ExecContext(t.Context(), "DROP INDEX idx_oidc_refresh_tokens_expires"); err != nil {
		t.Fatalf("drop index: %v", err)
	}
	const want = "oidcsql: oidc_refresh_tokens has no index on expires_at; create it from schema/postgres/v1.sql"
	if err := s.ValidateSchema(t.Context()); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("ValidateSchema error = %v, want it to contain %q", err, want)
	}
	if _, err := db.ExecContext(t.Context(), "CREATE INDEX embedder_refresh_sweep ON oidc_refresh_tokens (expires_at, grant_id)"); err != nil {
		t.Fatalf("create index: %v", err)
	}
	if err := s.ValidateSchema(t.Context()); err != nil {
		t.Fatalf("ValidateSchema with an equivalent index under another name: %v", err)
	}
}

// TestPostgres_ValidateSchema_MixedCaseNaming pins that a mixed-case
// WithNaming value validates: PostgreSQL folds the unquoted identifier
// to lower case, so the catalog never records the name as written.
func TestPostgres_ValidateSchema_MixedCaseNaming(t *testing.T) {
	t.Parallel()
	db := newPostgresDBFactory(t)(t)
	s, err := oidcsql.New(db, oidcsql.Postgres(), oidcsql.WithNaming(map[string]string{
		"clients":  "Acme_Clients",
		"sessions": "AcmeSessions",
	}))
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(t.Context()); err != nil {
		t.Fatalf("Migrate with mixed-case names: %v", err)
	}
	if err := s.ValidateSchema(t.Context()); err != nil {
		t.Fatalf("ValidateSchema with mixed-case names: %v", err)
	}
}
