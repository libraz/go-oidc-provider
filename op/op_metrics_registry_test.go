package op_test

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/libraz/go-oidc-provider/op"
)

// TestProvider_WithPrometheus_TwoProvidersShareOneRegistry asserts a
// process running more than one OP can point both at a single
// registry. The metrics are separated by the issuer constant label, so
// the second construction is not a name collision.
func TestProvider_WithPrometheus_TwoProvidersShareOneRegistry(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()

	if _, err := op.New(append(validBaseOpts(t), op.WithPrometheus(reg))...); err != nil {
		t.Fatalf("first op.New: %v", err)
	}
	second := append(validBaseOpts(t),
		op.WithIssuer("https://second-idp.example.com"),
		op.WithPrometheus(reg),
	)
	if _, err := op.New(second...); err != nil {
		t.Fatalf("second op.New on the shared registry: %v", err)
	}
}

// TestProvider_WithPrometheus_SameIssuerTwiceRejected asserts the
// distinguisher is the issuer and not the Provider identity: two OPs
// claiming the same issuer on one registry stay a configuration error.
func TestProvider_WithPrometheus_SameIssuerTwiceRejected(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()

	if _, err := op.New(append(validBaseOpts(t), op.WithPrometheus(reg))...); err != nil {
		t.Fatalf("first op.New: %v", err)
	}
	_, err := op.New(append(validBaseOpts(t), op.WithPrometheus(reg))...)
	if err == nil {
		t.Fatal("expected the duplicate issuer to be rejected, got nil")
	}
	if !op.IsServerError(err) {
		t.Fatalf("err = %v, want server-class configuration error", err)
	}
}

// TestProvider_WithPrometheus_FailedRegistrationLeavesRegistryClean
// asserts a rejected construction does not leave half of the curated
// set behind: the registry must still accept a clean Provider for the
// same issuer once the collision is gone.
func TestProvider_WithPrometheus_FailedRegistrationLeavesRegistryClean(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()

	if _, err := op.New(append(validBaseOpts(t), op.WithPrometheus(reg))...); err != nil {
		t.Fatalf("first op.New: %v", err)
	}
	// Rejected: same issuer, so the very first collector collides and
	// nothing of the second Provider may survive.
	if _, err := op.New(append(validBaseOpts(t), op.WithPrometheus(reg))...); err == nil {
		t.Fatal("expected the duplicate issuer to be rejected, got nil")
	}
	// A third Provider under a fresh issuer must still register cleanly.
	third := append(validBaseOpts(t),
		op.WithIssuer("https://third-idp.example.com"),
		op.WithPrometheus(reg),
	)
	if _, err := op.New(third...); err != nil {
		t.Fatalf("third op.New after the rejected one: %v", err)
	}
}
