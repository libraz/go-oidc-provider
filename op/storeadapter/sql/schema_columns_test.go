package oidcsql_test

import (
	"context"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

func TestValidateSchema_MissingV1ColumnFailsFullAndScopedChecks(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, db := newValidateStore(t)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	for _, stmt := range []string{
		"DROP TABLE oidc_authn_lockouts",
		"CREATE TABLE oidc_authn_lockouts (subject TEXT PRIMARY KEY, failed_count INTEGER NOT NULL)",
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	scoped, ok := s.AuthnLockouts().(store.SchemaValidator)
	if !ok {
		t.Fatal("AuthnLockouts is not a SchemaValidator")
	}
	for name, err := range map[string]error{"full": s.ValidateSchema(ctx), "scoped": scoped.ValidateSchema(ctx)} {
		if err == nil {
			t.Fatalf("%s check passed with columns missing", name)
		}
		if !strings.Contains(err.Error(), "schema for oidc_authn_lockouts is missing required columns: ") {
			t.Errorf("%s check: unexpected error %q", name, err)
		}
		if strings.Contains(err.Error(), "apply migration") {
			t.Errorf("%s check: v1.0.0 columns have no migration, got hint in %q", name, err)
		}
	}
}

func TestValidateSchema_ExtraEmbedderColumnAllowed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, db := newValidateStore(t)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := db.ExecContext(ctx, "ALTER TABLE oidc_authn_lockouts ADD COLUMN embedder_note TEXT"); err != nil {
		t.Fatalf("add column: %v", err)
	}
	if err := s.ValidateSchema(ctx); err != nil {
		t.Fatalf("ValidateSchema with an extra column: %v", err)
	}
}

func TestValidateSchema_MissingTableNamesRemedyOnce(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := newValidateStore(t)
	err := s.ValidateSchema(ctx)
	if err == nil {
		t.Fatal("ValidateSchema passed on an empty database")
	}
	msg := err.Error()
	if n := strings.Count(msg, "Store.Migrations()"); n != 1 {
		t.Errorf("remedy appears %d times, want once: %q", n, msg)
	}
	if !strings.Contains(msg, "Store.Migrate") || !strings.Contains(msg, "schema/sqlite/v1.sql") {
		t.Errorf("remedy incomplete: %q", msg)
	}
}
