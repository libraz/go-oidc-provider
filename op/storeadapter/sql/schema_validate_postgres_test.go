//go:build testcontainers

package oidcsql_test

import (
	"testing"

	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

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
