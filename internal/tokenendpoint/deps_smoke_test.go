package tokenendpoint_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/tokenendpoint"
	"github.com/libraz/go-oidc-provider/op/store"
)

// TestDeps_WaveTwoPlumbing pins the ADR 0025 Wave 2 plumbing surface:
// the new GrantRevocations and RevocationStrategy fields on
// [tokenendpoint.Deps] must be reachable so Waves 4 / 5 can land their
// handler logic without re-touching the wiring layer in op.go. The
// test is a build-time smoke check; the zero values are intentional
// because Wave 2 does not yet consume the fields.
func TestDeps_WaveTwoPlumbing(t *testing.T) {
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
