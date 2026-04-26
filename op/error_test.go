package op_test

import (
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestErrorIs_SentinelsAreDistinct fixes the contract that two
// configuration-class sentinels which happen to share an OAuth-style
// Code MUST NOT be interchangeable under [errors.Is]. The matcher uses
// pointer identity, so [op.ErrIssuerRequired] and [op.ErrStoreRequired]
// — both Code "configuration_error" — must not collide.
func TestErrorIs_SentinelsAreDistinct(t *testing.T) {
	t.Parallel()

	if errors.Is(op.ErrIssuerRequired, op.ErrStoreRequired) {
		t.Fatal("ErrIssuerRequired must not match ErrStoreRequired under errors.Is")
	}
	if errors.Is(op.ErrStoreRequired, op.ErrIssuerRequired) {
		t.Fatal("ErrStoreRequired must not match ErrIssuerRequired under errors.Is")
	}
	if errors.Is(op.ErrKeysetRequired, op.ErrIssuerRequired) {
		t.Fatal("ErrKeysetRequired must not match ErrIssuerRequired under errors.Is")
	}
	if !errors.Is(op.ErrIssuerRequired, op.ErrIssuerRequired) {
		t.Fatal("ErrIssuerRequired must match itself under errors.Is")
	}
}

// TestErrorIs_CodeClassPredicatesUnaffected confirms that dropping the
// code-only Is shim did not regress [op.IsClientError] /
// [op.IsServerError]: those predicates inspect Code on a wrapped
// *Error via [errors.As] and stay independent of pointer identity.
func TestErrorIs_CodeClassPredicatesUnaffected(t *testing.T) {
	t.Parallel()

	if !op.IsServerError(op.ErrIssuerRequired) {
		t.Fatal("IsServerError must classify ErrIssuerRequired (configuration_error)")
	}
	if !op.IsServerError(op.ErrStoreRequired) {
		t.Fatal("IsServerError must classify ErrStoreRequired (configuration_error)")
	}
	if op.IsClientError(op.ErrIssuerRequired) {
		t.Fatal("IsClientError must not classify ErrIssuerRequired")
	}
}
