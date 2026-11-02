package oidcsql_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// TestGC_SkipsMissingPARTable pins that a deployment without PAR, which
// need not create oidc_par_records, still sweeps every other table.
func TestGC_SkipsMissingPARTable(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	base := contract.Reference
	db := openSQLite(t)
	s, err := oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithClock(&fixedClock{now: base}))
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := s.Interactions().Save(ctx, &store.Interaction{
		ID: "ix-1", ClientID: "c", Step: "login", RawState: []byte("{}"),
		ExpiresAt: base.Add(time.Hour), CreatedAt: base, UpdatedAt: base,
	}); err != nil {
		t.Fatalf("save interaction: %v", err)
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE oidc_par_records"); err != nil {
		t.Fatalf("drop par_records: %v", err)
	}

	stats, err := s.GC(ctx, base.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("GC with oidc_par_records missing: %v", err)
	}
	if stats.PushedAuthRequests != 0 || stats.Interactions != 1 {
		t.Fatalf("GC reported %+v, want PushedAuthRequests 0 and Interactions 1", stats)
	}
}

// TestGC_SkipsEveryConditionalTableWhenMissing pins that a table the
// configuration may leave uncreated is skipped on its own, whichever
// combination is absent, while the sweeps for existing tables still run.
func TestGC_SkipsEveryConditionalTableWhenMissing(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	base := contract.Reference
	db := openSQLite(t)
	s, err := oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithClock(&fixedClock{now: base}))
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := s.ConsumedJTIs().Mark(ctx, "jti-1", base.Add(time.Hour)); err != nil {
		t.Fatalf("Mark: %v", err)
	}
	for _, table := range []string{"oidc_authorization_codes", "oidc_par_records", "oidc_interactions", "oidc_sessions"} {
		if _, err := db.ExecContext(ctx, "DROP TABLE "+table); err != nil {
			t.Fatalf("drop %s: %v", table, err)
		}
	}

	stats, err := s.GC(ctx, base.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("GC with the conditional tables missing: %v", err)
	}
	if stats.ConsumedJTIs != 1 {
		t.Fatalf("GC reported %+v, want ConsumedJTIs 1", stats)
	}
}

// TestGC_MissingRequiredTableDoesNotStarveOtherSweeps pins that a table
// every configuration checks fails its own sweep with an error, and that
// the sweeps after it still run.
func TestGC_MissingRequiredTableDoesNotStarveOtherSweeps(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	base := contract.Reference
	db := openSQLite(t)
	s, err := oidcsql.New(db, oidcsql.SQLite(), oidcsql.WithClock(&fixedClock{now: base}))
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if err := s.ConsumedJTIs().Mark(ctx, "jti-1", base.Add(time.Hour)); err != nil {
		t.Fatalf("Mark: %v", err)
	}
	if _, err := db.ExecContext(ctx, "DROP TABLE oidc_refresh_tokens"); err != nil {
		t.Fatalf("drop refresh_tokens: %v", err)
	}

	stats, err := s.GC(ctx, base.Add(2*time.Hour))
	if err == nil || !strings.Contains(err.Error(), "gc.refreshTokens") {
		t.Fatalf("GC with oidc_refresh_tokens missing = %v, want a gc.refreshTokens error", err)
	}
	if stats.ConsumedJTIs != 1 {
		t.Fatalf("GC reported %+v, want ConsumedJTIs 1 despite the failing sweep", stats)
	}
}
