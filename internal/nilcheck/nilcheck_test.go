package nilcheck_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/nilcheck"
)

func TestIsNil(t *testing.T) {
	t.Parallel()

	var nilPtr *int
	var nilMap map[string]int
	var nilFunc func()
	one := 1
	cases := []struct {
		name string
		v    any
		want bool
	}{
		{"untyped nil", nil, true},
		{"typed nil pointer", nilPtr, true},
		{"typed nil map", nilMap, true},
		{"typed nil func", nilFunc, true},
		{"non-nil pointer", &one, false},
		{"value kind", 1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := nilcheck.IsNil(tc.v); got != tc.want {
				t.Fatalf("IsNil = %v, want %v", got, tc.want)
			}
		})
	}
}
