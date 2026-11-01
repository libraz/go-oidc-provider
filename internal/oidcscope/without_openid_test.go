package oidcscope_test

import (
	"slices"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/oidcscope"
)

func TestWithoutOpenID(t *testing.T) {
	t.Parallel()

	in := []string{"openid", "profile", "openid", "email"}
	got := oidcscope.WithoutOpenID(in)
	if want := []string{"profile", "email"}; !slices.Equal(got, want) {
		t.Fatalf("WithoutOpenID = %v, want %v", got, want)
	}
	if !slices.Equal(in, []string{"openid", "profile", "openid", "email"}) {
		t.Fatalf("input mutated: %v", in)
	}
	if got := oidcscope.WithoutOpenID(nil); len(got) != 0 {
		t.Fatalf("WithoutOpenID(nil) = %v, want empty", got)
	}
}
