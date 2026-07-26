package profile_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op/profile"
)

func TestProfile_String(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   profile.Profile
		want string
	}{
		{"baseline", profile.Baseline, "baseline"},
		{"fapi2-baseline", profile.FAPI2Baseline, "fapi2-baseline"},
		{"fapi2-message-signing", profile.FAPI2MessageSigning, "fapi2-message-signing"},
		{"fapi-ciba", profile.FAPICIBA, "fapi-ciba"},
		{"zero", profile.Profile(0), ""},
		{"unknown", profile.Profile(99), ""},
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

func TestProfile_IsValid(t *testing.T) {
	t.Parallel()

	all := []profile.Profile{
		profile.Baseline,
		profile.FAPI2Baseline,
		profile.FAPI2MessageSigning,
		profile.FAPICIBA,
	}
	for _, p := range all {
		if !p.IsValid() {
			t.Errorf("%s must be valid", p)
		}
	}
	if profile.Profile(0).IsValid() {
		t.Error("zero must be invalid")
	}
	if profile.Profile(200).IsValid() {
		t.Error("out-of-range must be invalid")
	}
}

func TestRequiresAccessTokenRevocation(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   profile.Profile
		want bool
	}{
		{"fapi2-baseline", profile.FAPI2Baseline, true},
		{"fapi2-message-signing", profile.FAPI2MessageSigning, true},
		{"fapi-ciba", profile.FAPICIBA, true},
		{"baseline", profile.Baseline, false},
		{"zero", profile.Profile(0), false},
		{"unknown", profile.Profile(99), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := profile.RequiresAccessTokenRevocation(tc.in); got != tc.want {
				t.Errorf("RequiresAccessTokenRevocation(%s) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
