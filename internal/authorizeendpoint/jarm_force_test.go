// White-box test for [jarmModeMissing], the predicate that gates the
// FAPI 2.0 Message Signing §5.5 "every authorize response MUST be
// JARM-wrapped" rule. The predicate composes a Deps-level boolean
// with the request-level [jarmFeatureRequested]; locking its truth
// table here keeps a future refactor from silently regressing the
// gate.
//
//nolint:testpackage // intentional white-box test for unexported predicate.
package authorizeendpoint

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorize"
)

func TestJARMModeMissing(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		require   bool
		mode      string
		wantBlock bool
	}{
		// Flag off: nothing is rejected, regardless of mode.
		{"disabled-empty", false, "", false},
		{"disabled-query", false, "query", false},
		{"disabled-form_post", false, "form_post", false},
		{"disabled-jwt", false, "jwt", false},
		{"disabled-query.jwt", false, "query.jwt", false},

		// Flag on, request did NOT opt into JARM: must be blocked.
		{"enabled-empty", true, "", true},
		{"enabled-query", true, "query", true},
		{"enabled-form_post", true, "form_post", true},

		// Flag on, request opted into a JARM mode: passes the gate.
		// All four JARM aliases must be accepted so the gate does not
		// reject conformant clients that picked a different transport.
		{"enabled-jwt", true, "jwt", false},
		{"enabled-query.jwt", true, "query.jwt", false},
		{"enabled-fragment.jwt", true, "fragment.jwt", false},
		{"enabled-form_post.jwt", true, "form_post.jwt", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			deps := resolved{Deps: Deps{RequireJARMResponseMode: tc.require}}
			req := &authorize.Request{ResponseMode: tc.mode}
			if got := jarmModeMissing(deps, req); got != tc.wantBlock {
				t.Errorf("jarmModeMissing(require=%v, mode=%q) = %v, want %v",
					tc.require, tc.mode, got, tc.wantBlock)
			}
		})
	}
}
