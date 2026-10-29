package oidcsql_test

import (
	"context"
	databasesql "database/sql"
	"strings"
	"testing"

	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

func newValidateStore(t *testing.T, opts ...oidcsql.Option) (*oidcsql.Store, *databasesql.DB) {
	t.Helper()
	db := openSQLite(t)
	s, err := oidcsql.New(db, oidcsql.SQLite(), opts...)
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	return s, db
}

func sqliteTableExists(t *testing.T, db *databasesql.DB, table string) bool {
	t.Helper()
	var n int
	err := db.QueryRowContext(context.Background(),
		"SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?", table).Scan(&n)
	if err != nil {
		t.Fatalf("inspect sqlite_master: %v", err)
	}
	return n > 0
}

func TestValidateSchema_OK(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, _ := newValidateStore(t)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := s.ValidateSchema(ctx); err != nil {
		t.Fatalf("ValidateSchema after Migrate: %v", err)
	}
}

func TestValidateSchema_MissingTable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, db := newValidateStore(t)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE oidc_consumed_jtis"); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	err := s.ValidateSchema(ctx)
	if err == nil {
		t.Fatal("ValidateSchema succeeded with a table missing")
	}
	if !strings.Contains(err.Error(), "oidc_consumed_jtis") || !strings.Contains(err.Error(), "is missing") {
		t.Fatalf("error %q does not name the missing table", err)
	}
}

func TestValidateSchema_MissingColumn(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, db := newValidateStore(t)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if _, err := db.ExecContext(ctx, "ALTER TABLE oidc_totp_secrets DROP COLUMN row_version"); err != nil {
		t.Fatalf("drop column: %v", err)
	}
	err := s.ValidateSchema(ctx)
	if err == nil {
		t.Fatal("ValidateSchema succeeded with a column missing")
	}
	if !strings.Contains(err.Error(), "oidc_totp_secrets") || !strings.Contains(err.Error(), "row_version") {
		t.Fatalf("error %q does not name the table and column", err)
	}
}

func TestValidateSchema_MissingPreviousSecretColumns(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, db := newValidateStore(t)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	for _, col := range []string{"previous_secret_hash", "previous_secret_expires_at"} {
		if _, err := db.ExecContext(ctx, "ALTER TABLE oidc_clients DROP COLUMN "+col); err != nil {
			t.Fatalf("drop column %s: %v", col, err)
		}
	}
	err := s.ValidateSchema(ctx)
	if err == nil {
		t.Fatal("ValidateSchema succeeded with the previous-secret columns missing")
	}
	for _, want := range []string{"oidc_clients", "previous_secret_hash", "previous_secret_expires_at"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}
}

func TestValidateSchema_DoesNotCreate(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, db := newValidateStore(t)
	err := s.ValidateSchema(ctx)
	if err == nil {
		t.Fatal("ValidateSchema succeeded against an empty database")
	}
	if !strings.Contains(err.Error(), "is missing") {
		t.Fatalf("error %q does not report a missing table", err)
	}
	if sqliteTableExists(t, db, "oidc_clients") {
		t.Fatal("ValidateSchema created a table")
	}
}

func TestValidateSchema_WithNaming(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, db := newValidateStore(t, oidcsql.WithNaming(map[string]string{
		"clients":  "acme_clients",
		"sessions": "acme_sessions",
	}))
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := s.ValidateSchema(ctx); err != nil {
		t.Fatalf("ValidateSchema with custom names: %v", err)
	}
	if !sqliteTableExists(t, db, "acme_clients") || sqliteTableExists(t, db, "oidc_clients") {
		t.Fatal("custom table names were not applied")
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE acme_sessions"); err != nil {
		t.Fatalf("drop table: %v", err)
	}
	if err := s.ValidateSchema(ctx); err == nil || !strings.Contains(err.Error(), "acme_sessions") {
		t.Fatalf("error %v does not name the renamed table", err)
	}
}
