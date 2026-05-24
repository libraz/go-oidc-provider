package authorizeendpoint

import (
	"reflect"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// TestAuthorizationDetailsCovered pins the consent-coverage predicate that
// gates silent-mint: a request is "covered" only when every requested RFC
// 9396 authorization_details element deep-equals an element already on the
// grant. An empty request is trivially covered; a nil grant or a single new
// element is not, forcing the dispatcher through consent.
func TestAuthorizationDetailsCovered(t *testing.T) {
	t.Parallel()

	payment := map[string]any{"type": "payment_initiation", "amount": "100"}
	other := map[string]any{"type": "account_information"}

	tests := []struct {
		name      string
		requested []map[string]any
		grant     *store.Grant
		want      bool
	}{
		{
			name:      "empty request is covered",
			requested: nil,
			grant:     nil,
			want:      true,
		},
		{
			name:      "nil grant cannot cover a non-empty request",
			requested: []map[string]any{payment},
			grant:     nil,
			want:      false,
		},
		{
			name:      "grant with matching element covers the request",
			requested: []map[string]any{payment},
			grant:     &store.Grant{AuthorizationDetails: []map[string]any{payment}},
			want:      true,
		},
		{
			name:      "a new element is not covered",
			requested: []map[string]any{payment, other},
			grant:     &store.Grant{AuthorizationDetails: []map[string]any{payment}},
			want:      false,
		},
		{
			name:      "grant without authorization_details cannot cover",
			requested: []map[string]any{payment},
			grant:     &store.Grant{AuthorizationDetails: nil},
			want:      false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := authorizationDetailsCovered(tc.requested, tc.grant); got != tc.want {
				t.Errorf("authorizationDetailsCovered=%v want %v", got, tc.want)
			}
		})
	}
}

// TestAppendAuthorizationDetails pins the Grant Management merge dedup: an
// add-element deep-equal to an existing one is skipped so a repeated merge
// of the same authorization_details does not accumulate duplicates, while
// distinct elements accumulate. The result also must not alias the inputs.
func TestAppendAuthorizationDetails(t *testing.T) {
	t.Parallel()

	base := []map[string]any{{"type": "payment_initiation", "amount": "100"}}

	t.Run("duplicate element is skipped", func(t *testing.T) {
		t.Parallel()
		add := []map[string]any{{"type": "payment_initiation", "amount": "100"}}
		out := appendAuthorizationDetails(base, add)
		if len(out) != 1 {
			t.Fatalf("length=%d want 1 (duplicate not deduped)", len(out))
		}
	})

	t.Run("distinct element accumulates", func(t *testing.T) {
		t.Parallel()
		add := []map[string]any{{"type": "account_information"}}
		out := appendAuthorizationDetails(base, add)
		if len(out) != 2 {
			t.Fatalf("length=%d want 2", len(out))
		}
	})

	t.Run("mix of duplicate and new", func(t *testing.T) {
		t.Parallel()
		add := []map[string]any{
			{"type": "payment_initiation", "amount": "100"}, // dup of base
			{"type": "account_information"},                 // new
		}
		out := appendAuthorizationDetails(base, add)
		if len(out) != 2 {
			t.Fatalf("length=%d want 2 (dedup mixed with new)", len(out))
		}
	})

	t.Run("result does not alias the base maps", func(t *testing.T) {
		t.Parallel()
		out := appendAuthorizationDetails(base, nil)
		out[0]["amount"] = "999"
		if reflect.DeepEqual(out[0], base[0]) {
			t.Error("result element aliases the base map (mutation leaked)")
		}
	})
}
