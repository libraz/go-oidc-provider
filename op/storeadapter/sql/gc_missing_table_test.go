package oidcsql_test

import (
	"context"
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
