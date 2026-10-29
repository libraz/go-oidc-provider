package op_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
)

// TestExternalStepSentinel_MatchesInternal pins that the public sentinels
// are the orchestrator's own values: errors.Is holds in both directions,
// bare and wrapped, and the two classes stay distinct.
func TestExternalStepSentinel_MatchesInternal(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		public   error
		internal error
		other    error
	}{
		{name: "retry", public: op.ErrFactorRetry, internal: authn.ErrFactorRetry, other: authn.ErrFactorAbort},
		{name: "abort", public: op.ErrFactorAbort, internal: authn.ErrFactorAbort, other: authn.ErrFactorRetry},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !errors.Is(tc.public, tc.internal) || !errors.Is(tc.internal, tc.public) {
				t.Fatal("public and internal sentinels do not match")
			}
			if errors.Is(tc.public, tc.other) {
				t.Fatal("public sentinel matches the other class")
			}
			wrappedPublic := fmt.Errorf("external: %w", tc.public)
			wrappedInternal := fmt.Errorf("orchestrator: %w", tc.internal)
			if !errors.Is(wrappedPublic, tc.internal) {
				t.Error("wrapped public error does not match the internal sentinel")
			}
			if !errors.Is(wrappedInternal, tc.public) {
				t.Error("wrapped internal error does not match the public sentinel")
			}
		})
	}
}
