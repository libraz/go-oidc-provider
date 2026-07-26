package tokenendpoint_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/tokenendpoint"
	"github.com/libraz/go-oidc-provider/op/store"
)

// TestDeps_GrantRevocationFieldsAreReachable pins the revocation
// plumbing surface: the GrantRevocations and RevocationStrategy fields
// on [tokenendpoint.Deps] must stay assignable from outside the
// package, because the wiring layer in op.go is the only thing that
// populates them and a field that quietly loses its export breaks that
// wiring without failing any handler test. This is a build-time check;
// the zero values are the point, not an omission.
func TestDeps_GrantRevocationFieldsAreReachable(t *testing.T) {
	t.Parallel()

	var deps tokenendpoint.Deps
	// Compile-time reachability of the new fields.
	deps.GrantRevocations = nil
	deps.RevocationStrategy = store.RevocationStrategyGrantTombstone
	if deps.RevocationStrategy != store.RevocationStrategyGrantTombstone {
		t.Fatalf("RevocationStrategy field round-trip failed: got %v", deps.RevocationStrategy)
	}
	if deps.GrantRevocations != nil {
		t.Fatalf("GrantRevocations field round-trip failed: got %v", deps.GrantRevocations)
	}
}
