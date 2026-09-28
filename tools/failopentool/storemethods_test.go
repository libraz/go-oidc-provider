package main

import (
	"os"
	"path/filepath"
	"testing"
)

// writeStoreDir materialises a synthetic op/store package under a fresh
// repository root and returns the root.
func writeStoreDir(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, storeDir)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return root
}

// TestLoadStoreMethods_FindsTheReadsTheHardcodedListMissed is the
// concrete regression: IsRevoked, Has, and ListBySubject are real
// (T, error) reads on op/store interfaces that the old hand-maintained
// storeMethods table never named, so the gate could not see a call site
// that fails open on any of them.
func TestLoadStoreMethods_FindsTheReadsTheHardcodedListMissed(t *testing.T) {
	t.Parallel()
	root := writeStoreDir(t, map[string]string{
		"grant_revocation.go": `package store

import (
	"context"
	"time"
)

type GrantRevocationStore interface {
	RevokeGrant(ctx context.Context, t GrantTombstone) error
	IsRevoked(ctx context.Context, grantID, jti string, iat time.Time) (bool, error)
}
`,
		"jti.go": `package store

import "context"

type ConsumedJTIStore interface {
	Mark(ctx context.Context, jti string, expiresAt int64) error
	Has(ctx context.Context, jti string) (bool, error)
}
`,
		"grant.go": `package store

import "context"

type GrantStore interface {
	Save(ctx context.Context, g *Grant) error
	ListBySubject(ctx context.Context, subject string) ([]*Grant, error)
}
`,
	})
	got, err := loadStoreMethods(root)
	if err != nil {
		t.Fatalf("loadStoreMethods: %v", err)
	}
	for _, want := range []string{"IsRevoked", "Has", "ListBySubject"} {
		if !got[want] {
			t.Errorf("loadStoreMethods() missing %s; got %v", want, got)
		}
	}
}

// TestLoadStoreMethods_ExcludesAWriteThatOnlyReturnsError keeps the
// generated set to reads: a method whose failure has nowhere to fabricate
// a value is not the shape this gate is about, and folding it in would
// report every ordinary propagated write error as a storage call.
func TestLoadStoreMethods_ExcludesAWriteThatOnlyReturnsError(t *testing.T) {
	t.Parallel()
	root := writeStoreDir(t, map[string]string{
		"grant.go": `package store

import "context"

type GrantStore interface {
	Save(ctx context.Context, g *Grant) error
	Delete(ctx context.Context, id string) error
	Find(ctx context.Context, id string) (*Grant, error)
}
`,
	})
	got, err := loadStoreMethods(root)
	if err != nil {
		t.Fatalf("loadStoreMethods: %v", err)
	}
	if got["Save"] || got["Delete"] {
		t.Errorf("loadStoreMethods() included a write-only method: %v", got)
	}
	if !got["Find"] {
		t.Errorf("loadStoreMethods() dropped a real read: %v", got)
	}
}

// TestLoadStoreMethods_ExcludesAnAccessorWithNoErrorResult keeps the
// aggregate Store and Tx interfaces (whose methods hand back a substore
// or a handle, not a value-or-error) from being read as storage reads.
func TestLoadStoreMethods_ExcludesAnAccessorWithNoErrorResult(t *testing.T) {
	t.Parallel()
	root := writeStoreDir(t, map[string]string{
		"store.go": `package store

type Store interface {
	Grants() GrantStore
}
`,
		"grant.go": `package store

import "context"

type GrantStore interface {
	Find(ctx context.Context, id string) (*Grant, error)
}
`,
	})
	got, err := loadStoreMethods(root)
	if err != nil {
		t.Fatalf("loadStoreMethods: %v", err)
	}
	if got["Grants"] {
		t.Errorf("loadStoreMethods() treated an accessor as a read: %v", got)
	}
}
