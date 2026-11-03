//go:build example

// op_test.go — self-verification for the op.New wiring in op.go.

package main

import "testing"

// TestBuildProviderResolvesUsersFromTheLoginFlow checks that buildProvider
// constructs with no op.WithUserStore: the claim source is the
// PrimaryPassword store, since the aggregate carries no users.
func TestBuildProviderResolvesUsersFromTheLoginFlow(t *testing.T) {
	t.Parallel()

	storage, _ := newTestStore(t)
	if _, err := buildProvider(storage); err != nil {
		t.Fatalf("buildProvider: %v", err)
	}
}
