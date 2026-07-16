package authorize_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorize"
)

func TestErrorStringCarriesOAuthCodeAndDescription(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  *authorize.Error
		want string
	}{
		{
			name: "invalid request",
			err:  authorize.ErrClientIDRequired,
			want: "invalid_request: client_id is required",
		},
		{
			name: "unsupported response type",
			err:  authorize.ErrResponseTypeUnsupported,
			want: "unsupported_response_type: response_type must be code",
		},
		{
			name: "invalid target",
			err:  authorize.ErrResourceInvalid,
			want: "invalid_target: resource indicator is malformed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.err.Error(); got != tc.want {
				t.Fatalf("Error() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestErrorIsUsesSentinelIdentityThroughWrapping(t *testing.T) {
	t.Parallel()

	wrapped := fmt.Errorf("authorize validation failed: %w", authorize.ErrScopeNotPermitted)
	if !errors.Is(wrapped, authorize.ErrScopeNotPermitted) {
		t.Fatal("errors.Is did not match wrapped ErrScopeNotPermitted")
	}
	if errors.Is(wrapped, authorize.ErrScopeMissingOpenID) {
		t.Fatal("errors.Is matched a different authorize sentinel with the same wire code")
	}
}
