package feature_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op/feature"
)

func TestFlag_String(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   feature.Flag
		want string
	}{
		{"pkce", feature.PKCE, "pkce"},
		{"par", feature.PAR, "par"},
		{"jar", feature.JAR, "jar"},
		{"jarm", feature.JARM, "jarm"},
		{"dpop", feature.DPoP, "dpop"},
		{"mtls", feature.MTLS, "mtls"},
		{"introspect", feature.Introspect, "introspect"},
		{"revoke", feature.Revoke, "revoke"},
		{"zero", feature.Flag(0), ""},
		{"unknown", feature.Flag(99), ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := tc.in.String(); got != tc.want {
				t.Errorf("String()=%q want %q", got, tc.want)
			}
		})
	}
}

func TestFlag_IsValid(t *testing.T) {
	t.Parallel()

	all := []feature.Flag{
		feature.PKCE, feature.PAR, feature.JAR, feature.JARM,
		feature.DPoP, feature.MTLS, feature.Introspect, feature.Revoke,
	}
	for _, f := range all {
		if !f.IsValid() {
			t.Errorf("%s must be valid", f)
		}
	}
	if feature.Flag(0).IsValid() {
		t.Error("zero must be invalid")
	}
	if feature.Flag(200).IsValid() {
		t.Error("out-of-range must be invalid")
	}
}
