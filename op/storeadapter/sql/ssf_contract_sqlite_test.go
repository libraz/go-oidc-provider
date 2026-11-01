package oidcsql_test

import (
	"context"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
)

// ssfFactory adapts a store contract factory to the SSF contract, which
// takes the two substores rather than the aggregate.
func ssfFactory(f contract.Factory) contract.SSFFactory {
	return func(t *testing.T) contract.SSFBackend {
		t.Helper()
		s, ok := f(t).Store.(store.SharedSignalsStore)
		if !ok {
			t.Fatal("sql store does not implement store.SharedSignalsStore")
		}
		return contract.SSFBackend{Streams: s.SSFStreams(), Events: s.SSFEvents()}
	}
}

// TestSQLite_SSF runs the Shared Signals stream and SET-queue contract
// against SQLite.
func TestSQLite_SSF(t *testing.T) {
	t.Parallel()
	contract.RunSSF(t, ssfFactory(newSQLiteFactory(t)))
}

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
