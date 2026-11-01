package oidcscope_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/oidcscope"
)

func TestSubset(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name             string
		granted, allowed []string
		want             bool
	}{
		{name: "every entry present", granted: []string{"read", "write"}, allowed: []string{"profile", "write", "read"}, want: true},
		{name: "one entry absent", granted: []string{"read", "admin"}, allowed: []string{"read", "write"}, want: false},
		{name: "empty granted passes", granted: nil, allowed: []string{"read"}, want: true},
		{name: "empty granted against empty allowed passes", granted: nil, allowed: nil, want: true},
		{name: "empty allowed rejects a non-empty grant", granted: []string{"read"}, allowed: nil, want: false},
		{name: "case-sensitive", granted: []string{"Read"}, allowed: []string{"read"}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := oidcscope.Subset(tc.granted, tc.allowed); got != tc.want {
				t.Errorf("Subset(%v, %v)=%v want %v", tc.granted, tc.allowed, got, tc.want)
			}
		})
	}
}

func TestUnion(t *testing.T) {
	t.Parallel()

	got := oidcscope.Union([]string{"openid", "email"}, []string{"email", "profile", "profile"})
	want := []string{"openid", "email", "profile"}
	if len(got) != len(want) {
		t.Fatalf("Union = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Union = %v, want %v", got, want)
		}
	}
	if got := oidcscope.Union(nil, nil); len(got) != 0 {
		t.Fatalf("Union(nil, nil) = %v, want empty", got)
	}
}
