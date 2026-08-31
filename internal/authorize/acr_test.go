package authorize_test

import (
	"slices"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorize"
)

// TestRequestedACRValues pins the enumeration every authentication
// request surface reads: both spellings, parameter order first, one
// entry per value, non-string claims entries skipped.
func TestRequestedACRValues(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name string
		req  *authorize.Request
		want []string
	}{
		{name: "nil request", req: nil, want: nil},
		{name: "no acr asked for", req: &authorize.Request{}, want: nil},
		{
			name: "parameter only",
			req:  &authorize.Request{ACRValues: []string{"a", "b"}},
			want: []string{"a", "b"},
		},
		{
			name: "claims only",
			req: &authorize.Request{Claims: &authorize.ClaimsRequest{
				IDToken: map[string]authorize.ClaimSpec{
					"acr": {Essential: true, Values: []any{"c"}},
				},
			}},
			want: []string{"c"},
		},
		{
			name: "both spellings, parameter order first, deduplicated",
			req: &authorize.Request{
				ACRValues: []string{"a", "b"},
				Claims: &authorize.ClaimsRequest{
					IDToken: map[string]authorize.ClaimSpec{
						"acr": {Value: "b", Values: []any{"c", 42}},
					},
				},
			},
			want: []string{"a", "b", "c"},
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			if got := row.req.RequestedACRValues(); !slices.Equal(got, row.want) {
				t.Errorf("RequestedACRValues() = %v, want %v", got, row.want)
			}
		})
	}
}

// TestUnsupportedACRValue covers the allowlist the three authentication
// request surfaces share. The empty-list row is the compatibility
// posture: an OP that advertised nothing constrains nothing.
func TestUnsupportedACRValue(t *testing.T) {
	t.Parallel()

	advertised := []string{"urn:example:aal1", "urn:example:aal2"}
	rows := []struct {
		name      string
		req       *authorize.Request
		supported []string
		want      string
	}{
		{
			name:      "no advertisement admits anything",
			req:       &authorize.Request{ACRValues: []string{"urn:example:aal3"}},
			supported: nil,
		},
		{
			name:      "advertised value passes",
			req:       &authorize.Request{ACRValues: []string{"urn:example:aal2"}},
			supported: advertised,
		},
		{
			name:      "unadvertised parameter value is named",
			req:       &authorize.Request{ACRValues: []string{"urn:example:aal1", "urn:example:aal3"}},
			supported: advertised,
			want:      "urn:example:aal3",
		},
		{
			name: "unadvertised claims-spelled value is named",
			req: &authorize.Request{Claims: &authorize.ClaimsRequest{
				IDToken: map[string]authorize.ClaimSpec{
					"acr": {Essential: true, Values: []any{"urn:example:aal3"}},
				},
			}},
			supported: advertised,
			want:      "urn:example:aal3",
		},
		{
			name:      "request naming nothing passes",
			req:       &authorize.Request{},
			supported: advertised,
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			got, unsupported := row.req.UnsupportedACRValue(row.supported)
			if unsupported != (row.want != "") {
				t.Fatalf("UnsupportedACRValue() unsupported=%v want %v", unsupported, row.want != "")
			}
			if got != row.want {
				t.Errorf("UnsupportedACRValue() = %q, want %q", got, row.want)
			}
		})
	}
}
