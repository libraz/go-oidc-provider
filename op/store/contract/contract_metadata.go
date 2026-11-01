package contract

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// --- MetadataStore -------------------------------------------------------

// requireMetadata skips the current test when the backend has not
// provisioned [store.MetadataStore] ([store.Store.Metadata] MAY return
// nil per its godoc).
func requireMetadata(t *testing.T, s store.Store) store.MetadataStore {
	t.Helper()
	return requireSubstore(t, s, s.Metadata(), "Metadata()")
}

//nolint:gochecknoglobals // sub-test table; declared once so [Run] can iterate.
var metadataStoreCases = []subtest{
	{"SetGetRoundTrip", metadataSetGetRoundTrip},
	{"GetMissing", metadataGetMissing},
}

func metadataSetGetRoundTrip(t *testing.T, f Factory) {
	b := f(t)
	meta := requireMetadata(t, b.Store)
	ctx := context.Background()
	if err := meta.Set(ctx, "contract_test_key", "v1"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := meta.Get(ctx, "contract_test_key")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "v1" {
		t.Fatalf("Get: want %q, got %q", "v1", got)
	}
	// Set replaces any existing value under the key.
	if err := meta.Set(ctx, "contract_test_key", "v2"); err != nil {
		t.Fatalf("Set overwrite: %v", err)
	}
	got, err = meta.Get(ctx, "contract_test_key")
	if err != nil {
		t.Fatalf("Get after overwrite: %v", err)
	}
	if got != "v2" {
		t.Fatalf("Get after overwrite: want %q, got %q", "v2", got)
	}
}

func metadataGetMissing(t *testing.T, f Factory) {
	b := f(t)
	meta := requireMetadata(t, b.Store)
	_, err := meta.Get(context.Background(), "contract_absent_key")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get missing: want ErrNotFound, got %v", err)
	}
}
