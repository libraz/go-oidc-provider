package oidcscope_test

import (
	"reflect"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/oidcscope"
)

// TestParse_Cases exercises the RFC 6749 §3.3 scope-grammar edge cases
// the helper has to absorb without inventing tokens.
func TestParse_Cases(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want []string
	}{
		{name: "empty", in: "", want: nil},
		{name: "single_space", in: " ", want: nil},
		{name: "multiple_spaces", in: "   ", want: nil},
		{name: "single_token", in: "openid", want: []string{"openid"}},
		{name: "two_tokens", in: "openid profile", want: []string{"openid", "profile"}},
		{
			name: "three_tokens_with_repeated_whitespace",
			in:   "openid offline_access  profile",
			want: []string{"openid", "offline_access", "profile"},
		},
		{
			name: "leading_and_trailing_spaces",
			in:   " openid profile ",
			want: []string{"openid", "profile"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := oidcscope.Parse(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("Parse(%q) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}

// TestContainsOpenID covers the membership helper that gates id_token
// issuance.
func TestContainsOpenID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []string
		want bool
	}{
		{name: "nil", in: nil, want: false},
		{name: "empty", in: []string{}, want: false},
		{name: "absent", in: []string{"profile", "email"}, want: false},
		{name: "present_only", in: []string{"openid"}, want: true},
		{name: "present_first", in: []string{"openid", "profile"}, want: true},
		{name: "present_middle", in: []string{"profile", "openid", "email"}, want: true},
		{name: "case_sensitive", in: []string{"OpenID"}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := oidcscope.ContainsOpenID(tc.in); got != tc.want {
				t.Fatalf("ContainsOpenID(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestContainsOfflineAccess covers the membership helper that gates
// refresh-token issuance under the strict offline_access reading.
func TestContainsOfflineAccess(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []string
		want bool
	}{
		{name: "nil", in: nil, want: false},
		{name: "empty", in: []string{}, want: false},
		{name: "absent", in: []string{"openid", "profile"}, want: false},
		{name: "present_only", in: []string{"offline_access"}, want: true},
		{name: "present_with_openid", in: []string{"openid", "offline_access"}, want: true},
		{name: "present_last", in: []string{"openid", "profile", "offline_access"}, want: true},
		{name: "case_sensitive", in: []string{"Offline_Access"}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := oidcscope.ContainsOfflineAccess(tc.in); got != tc.want {
				t.Fatalf("ContainsOfflineAccess(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestConstants_Values pins the wire strings so a typo would surface
// as a test failure rather than as a silent spec drift.
func TestConstants_Values(t *testing.T) {
	t.Parallel()

	if oidcscope.ScopeOpenID != "openid" {
		t.Fatalf("ScopeOpenID = %q, want %q", oidcscope.ScopeOpenID, "openid")
	}
	if oidcscope.ScopeOfflineAccess != "offline_access" {
		t.Fatalf("ScopeOfflineAccess = %q, want %q", oidcscope.ScopeOfflineAccess, "offline_access")
	}
}
