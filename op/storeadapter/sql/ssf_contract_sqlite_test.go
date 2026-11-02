package oidcsql_test

import (
	"context"
	"strings"
	"testing"
)

// A database created before the SSF tables existed fails ValidateSchema
// with the migration that creates them.
func TestValidateSchema_MissingSSFTableNamesItsRelease(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, db := newValidateStore(t)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE oidc_ssf_events"); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	err := s.ValidateSchema(ctx)
	if err == nil {
		t.Fatal("ValidateSchema succeeded with oidc_ssf_events missing")
	}
	if want := "schema for oidc_ssf_events is missing; apply migration 000006_v1.5.0 (schema/migrations/sqlite/000006_v1.5.0.up.sql)"; !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not contain %q", err, want)
	}
}
