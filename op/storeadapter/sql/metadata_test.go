package oidcsql_test

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// TestSQLite_MetadataStore_RoundTrip exercises the substore against a
// fresh, migrated SQLite database. The cases mirror the contract the
// inmem adapter satisfies in full (Get-on-empty -> ErrNotFound,
// Set-then-Get round-trip, Set overwrites). Postgres / MySQL are
// covered by the testcontainers harness in metadata_postgres_test.go
// and metadata_mysql_test.go (build tag testcontainers).
func TestSQLite_MetadataStore_RoundTrip(t *testing.T) {
	t.Parallel()
	b := newSQLiteFactory(t)(t)
	meta := b.Store.Metadata()
	if meta == nil {
		t.Fatal("Store.Metadata() returned nil; the SQL adapter must implement MetadataStore")
	}
	ctx := context.Background()

	t.Run("Get on empty returns ErrNotFound", func(t *testing.T) {
		t.Parallel()
		if _, err := meta.Get(ctx, "absent_key"); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("Get(absent_key) err = %v, want %v", err, store.ErrNotFound)
		}
	})

	t.Run("Set then Get round-trips the value", func(t *testing.T) {
		t.Parallel()
		const key = "rt_key"
		const want = "v1"
		if err := meta.Set(ctx, key, want); err != nil {
			t.Fatalf("Set: %v", err)
		}
		got, err := meta.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got != want {
			t.Fatalf("Get returned %q, want %q", got, want)
		}
	})

	t.Run("Set overwrites prior value", func(t *testing.T) {
		t.Parallel()
		const key = "ow_key"
		if err := meta.Set(ctx, key, "first"); err != nil {
			t.Fatalf("Set first: %v", err)
		}
		if err := meta.Set(ctx, key, "second"); err != nil {
			t.Fatalf("Set second: %v", err)
		}
		got, err := meta.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got != "second" {
			t.Fatalf("Get returned %q, want %q", got, "second")
		}
	})

	t.Run("Empty value is preserved verbatim", func(t *testing.T) {
		t.Parallel()
		const key = "empty_key"
		if err := meta.Set(ctx, key, ""); err != nil {
			t.Fatalf("Set: %v", err)
		}
		got, err := meta.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got != "" {
			t.Fatalf("Get returned %q, want empty string", got)
		}
	})

	t.Run("SubjectMode marker round-trips", func(t *testing.T) {
		t.Parallel()
		// The library's first caller is the subject-mode immutability
		// gate; pin its specific key/value flow here so a regression
		// in either the schema or the upsert template surfaces as a
		// gate-shaped failure rather than a generic round-trip miss.
		if err := meta.Set(ctx, store.SubjectModeKey, store.SubjectModePublic); err != nil {
			t.Fatalf("Set SubjectMode: %v", err)
		}
		got, err := meta.Get(ctx, store.SubjectModeKey)
		if err != nil {
			t.Fatalf("Get SubjectMode: %v", err)
		}
		if got != store.SubjectModePublic {
			t.Fatalf("Get SubjectMode returned %q, want %q", got, store.SubjectModePublic)
		}
		// Switch the marker and confirm Get reflects the new value
		// (the upsert path the gate would refuse on the next boot).
		if err := meta.Set(ctx, store.SubjectModeKey, store.SubjectModePairwise); err != nil {
			t.Fatalf("Set SubjectMode (overwrite): %v", err)
		}
		got, err = meta.Get(ctx, store.SubjectModeKey)
		if err != nil {
			t.Fatalf("Get SubjectMode after overwrite: %v", err)
		}
		if got != store.SubjectModePairwise {
			t.Fatalf("Get SubjectMode after overwrite returned %q, want %q",
				got, store.SubjectModePairwise)
		}
	})
}

// TestSQLite_MetadataStore_NonNil pins the accessor's non-nil contract.
// The library's subject-mode immutability gate tolerates a nil accessor
// by skipping with a warning; once the SQL adapter wires the substore
// the accessor MUST stay non-nil so the gate fires.
func TestSQLite_MetadataStore_NonNil(t *testing.T) {
	t.Parallel()
	b := newSQLiteFactory(t)(t)
	if b.Store.Metadata() == nil {
		t.Fatal("Store.Metadata() returned nil; subject-mode immutability gate would skip")
	}
}

// Compile-time guard. The library reaches MetadataStore through the
// store.Store interface; pinning the satisfaction here makes a future
// signature drift fail at build time.
var _ store.MetadataStore = (interface {
	Get(context.Context, string) (string, error)
	Set(context.Context, string, string) error
})(nil)

// Suppress staticcheck "unused" complaint by referencing the adapter
// import from a no-op helper. The contract tests above exercise the
// real surface; this sentinel keeps the import required even if a
// future refactor relocates the constructor.
var _ = oidcsql.SQLite
