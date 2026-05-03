//go:build testcontainers

package oidcsql_test

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// TestPostgres_MetadataStore_RoundTrip mirrors the SQLite contract
// against a real PostgreSQL container. Postgres' ON CONFLICT(meta_key)
// upsert path is dialect-different from SQLite's identical-spelling
// path, so this test guards the dialect-dispatch branch.
func TestPostgres_MetadataStore_RoundTrip(t *testing.T) {
	t.Parallel()
	b := newPostgresFactory(t)(t)
	meta := b.Store.Metadata()
	if meta == nil {
		t.Fatal("Store.Metadata() returned nil; the SQL adapter must implement MetadataStore")
	}
	ctx := context.Background()

	if _, err := meta.Get(ctx, "absent_key"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get(absent_key) err = %v, want %v", err, store.ErrNotFound)
	}

	if err := meta.Set(ctx, "rt_key", "v1"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := meta.Get(ctx, "rt_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "v1" {
		t.Fatalf("Get returned %q, want %q", got, "v1")
	}

	if err := meta.Set(ctx, "rt_key", "v2"); err != nil {
		t.Fatalf("Set overwrite: %v", err)
	}
	got, err = meta.Get(ctx, "rt_key")
	if err != nil {
		t.Fatalf("Get after overwrite: %v", err)
	}
	if got != "v2" {
		t.Fatalf("Get after overwrite returned %q, want %q", got, "v2")
	}
}
