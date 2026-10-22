package oidcsql_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// TestSQLite_MigrateDetectsMissingAuthorizationStateColumns pins that a
// database whose authorization-code table predates the per-authorization
// columns fails Migrate instead of failing every code issuance later.
func TestSQLite_MigrateDetectsMissingAuthorizationStateColumns(t *testing.T) {
	t.Parallel()

	db := openSQLite(t)
	s, err := oidcsql.New(db, oidcsql.SQLite())
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if _, err := db.ExecContext(context.Background(), `
CREATE TABLE oidc_authorization_codes (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL DEFAULT '[]',
    resource TEXT NOT NULL DEFAULT '',
    code_challenge TEXT NOT NULL DEFAULT '',
    code_challenge_method TEXT NOT NULL DEFAULT '',
    nonce TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT '',
    dpop_jkt TEXT NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL,
    consumed_at INTEGER,
    created_at INTEGER NOT NULL
)`); err != nil {
		t.Fatalf("create legacy authorization code table: %v", err)
	}
	err = s.Migrate(context.Background())
	if err == nil {
		t.Fatal("Migrate succeeded against a legacy authorization code table; want missing-column error")
	}
	if !strings.Contains(err.Error(), "schema for oidc_authorization_codes is missing required columns") ||
		!strings.Contains(err.Error(), "authorization_recorded") {
		t.Fatalf("Migrate error=%v, want missing authorization-state columns", err)
	}
}

// TestSQLite_RowWithoutAuthorizationStateReadsUnrecorded pins the column
// defaults an older writer leaves behind: the row reads back with no
// per-authorization state and AuthorizationRecorded false, which is what
// sends readers to the grant.
func TestSQLite_RowWithoutAuthorizationStateReadsUnrecorded(t *testing.T) {
	t.Parallel()

	db := openSQLite(t)
	s, err := oidcsql.New(db, oidcsql.SQLite())
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	ctx := context.Background()
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	const codeID = "code-legacy-row"
	// An older writer's INSERT names none of the authorization-state columns.
	expires := time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano()
	if _, err := db.ExecContext(ctx, `INSERT INTO oidc_authorization_codes
		(id, client_id, grant_id, subject, redirect_uri, scope, expires_at, created_at)
		VALUES (?, 'client', 'grant', 'sub', 'https://rp.example.com/cb', '["openid"]', ?, 1)`,
		patterns.Digest(codeID), expires); err != nil {
		t.Fatalf("legacy insert: %v", err)
	}
	got, err := s.AuthorizationCodes().Find(ctx, codeID)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if got.AuthorizationRecorded || !got.AuthTime.IsZero() || got.ACR != "" || len(got.AMR) != 0 ||
		len(got.AuthorizationDetails) != 0 || len(got.Claims) != 0 {
		t.Fatalf("legacy row read back %+v; want no authorization state and recorded=false", got)
	}
}
