package profile_test

import (
	"slices"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
)

func TestRequiredFeatures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   profile.Profile
		want []feature.Flag
	}{
		{
			"fapi2-baseline",
			profile.FAPI2Baseline,
			[]feature.Flag{feature.PAR, feature.JAR},
		},
		{
			"fapi2-message-signing",
			profile.FAPI2MessageSigning,
			[]feature.Flag{feature.PAR, feature.JAR, feature.JARM},
		},
		{"fapi-ciba", profile.FAPICIBA, nil},
		{"igov-high", profile.IGovHigh, nil},
		{"zero", profile.Profile(0), nil},
		{"unknown", profile.Profile(99), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := profile.RequiredFeatures(tc.in)
			if !slices.Equal(got, tc.want) {
				t.Errorf("RequiredFeatures(%s) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestRequiredAnyOf(t *testing.T) {
	t.Parallel()

	t.Run("baseline-requires-dpop-or-mtls", func(t *testing.T) {
		t.Parallel()
		got := profile.RequiredAnyOf(profile.FAPI2Baseline)
		if len(got) != 1 {
			t.Fatalf("RequiredAnyOf(FAPI2Baseline) = %v, want one set", got)
		}
		if !slices.Equal(got[0], []feature.Flag{feature.DPoP, feature.MTLS}) {
			t.Errorf("RequiredAnyOf(FAPI2Baseline)[0] = %v, want [DPoP MTLS]", got[0])
		}
	})

	t.Run("message-signing-inherits-anyof", func(t *testing.T) {
		t.Parallel()
		got := profile.RequiredAnyOf(profile.FAPI2MessageSigning)
		if len(got) != 1 || !slices.Equal(got[0], []feature.Flag{feature.DPoP, feature.MTLS}) {
			t.Errorf("RequiredAnyOf(FAPI2MessageSigning) = %v, want [[DPoP MTLS]]", got)
		}
	})

	t.Run("zero-and-deferred-profiles-have-no-anyof", func(t *testing.T) {
		t.Parallel()
		for _, p := range []profile.Profile{profile.Profile(0), profile.FAPICIBA, profile.IGovHigh, profile.Profile(99)} {
			if got := profile.RequiredAnyOf(p); got != nil {
				t.Errorf("RequiredAnyOf(%v) = %v, want nil", p, got)
			}
		}
	})

	t.Run("returns-fresh-slice", func(t *testing.T) {
		t.Parallel()
		first := profile.RequiredAnyOf(profile.FAPI2Baseline)
		second := profile.RequiredAnyOf(profile.FAPI2Baseline)
		first[0][0] = feature.Flag(0)
		if second[0][0] == feature.Flag(0) {
			t.Error("RequiredAnyOf returned aliased inner slice; mutation leaked across calls")
		}
	})
}

func TestMaxAccessTokenTTL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   profile.Profile
		want time.Duration
	}{
		{"fapi2-baseline", profile.FAPI2Baseline, 10 * time.Minute},
		{"fapi2-message-signing", profile.FAPI2MessageSigning, 10 * time.Minute},
		{"fapi-ciba", profile.FAPICIBA, 0},
		{"igov-high", profile.IGovHigh, 0},
		{"zero", profile.Profile(0), 0},
		{"unknown", profile.Profile(99), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := profile.MaxAccessTokenTTL(tc.in)
			if got != tc.want {
				t.Errorf("MaxAccessTokenTTL(%s) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestAllowedClientAuthMethods(t *testing.T) {
	t.Parallel()

	fapi2Allowed := []string{"private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"}

	cases := []struct {
		name string
		in   profile.Profile
		want []string
	}{
		{"fapi2-baseline", profile.FAPI2Baseline, fapi2Allowed},
		{"fapi2-message-signing", profile.FAPI2MessageSigning, fapi2Allowed},
		{"fapi-ciba", profile.FAPICIBA, nil},
		{"igov-high", profile.IGovHigh, nil},
		{"zero", profile.Profile(0), nil},
		{"unknown", profile.Profile(99), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := profile.AllowedClientAuthMethods(tc.in)
			if !slices.Equal(got, tc.want) {
				t.Errorf("AllowedClientAuthMethods(%s) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}

	t.Run("returns-fresh-slice", func(t *testing.T) {
		t.Parallel()
		first := profile.AllowedClientAuthMethods(profile.FAPI2Baseline)
		second := profile.AllowedClientAuthMethods(profile.FAPI2Baseline)
		first[0] = "TAINTED"
		if second[0] == "TAINTED" {
			t.Error("AllowedClientAuthMethods returned aliased slice; mutation leaked across calls")
		}
	})
}
