package profile_test

import (
	"slices"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
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
		{
			"fapi-ciba",
			profile.FAPICIBA,
			[]feature.Flag{feature.JAR},
		},
		{"baseline", profile.Baseline, nil},
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

func TestRequiresPKCE(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   profile.Profile
		want bool
	}{
		{"baseline", profile.Baseline, true},
		{"fapi2-baseline", profile.FAPI2Baseline, true},
		{"fapi2-message-signing", profile.FAPI2MessageSigning, true},
		{"fapi-ciba", profile.FAPICIBA, false},
		{"zero", profile.Profile(0), false},
		{"unknown", profile.Profile(99), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := profile.RequiresPKCE(tc.in); got != tc.want {
				t.Errorf("RequiresPKCE(%s) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestRequiredGrants(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   profile.Profile
		want []grant.Type
	}{
		{"fapi-ciba", profile.FAPICIBA, []grant.Type{grant.CIBA}},
		{"baseline", profile.Baseline, nil},
		{"fapi2-baseline", profile.FAPI2Baseline, nil},
		{"fapi2-message-signing", profile.FAPI2MessageSigning, nil},
		{"zero", profile.Profile(0), nil},
		{"unknown", profile.Profile(99), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := profile.RequiredGrants(tc.in)
			if !slices.Equal(got, tc.want) {
				t.Errorf("RequiredGrants(%s) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}

	t.Run("returns-fresh-slice", func(t *testing.T) {
		t.Parallel()
		first := profile.RequiredGrants(profile.FAPICIBA)
		second := profile.RequiredGrants(profile.FAPICIBA)
		first[0] = grant.Type(0)
		if second[0] == grant.Type(0) {
			t.Error("RequiredGrants returned aliased slice; mutation leaked across calls")
		}
	})
}

func TestRequiredAnyOf(t *testing.T) {
	t.Parallel()

	t.Run("fapi2-baseline-requires-dpop-or-mtls", func(t *testing.T) {
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

	t.Run("fapi-ciba-inherits-anyof", func(t *testing.T) {
		t.Parallel()
		got := profile.RequiredAnyOf(profile.FAPICIBA)
		if len(got) != 1 || !slices.Equal(got[0], []feature.Flag{feature.DPoP, feature.MTLS}) {
			t.Errorf("RequiredAnyOf(FAPICIBA) = %v, want [[DPoP MTLS]]", got)
		}
	})

	t.Run("profiles-without-anyof", func(t *testing.T) {
		t.Parallel()
		for _, p := range []profile.Profile{profile.Baseline, profile.Profile(0), profile.Profile(99)} {
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
		{"fapi-ciba", profile.FAPICIBA, 10 * time.Minute},
		{"baseline", profile.Baseline, 0},
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

// TestMaxRequestObjectAge pins the request-object age cap each profile
// carries. The FAPI family grants a 60-minute validity window
// (FAPI 2.0 Message Signing §5.6); a verifier left on its own, shorter
// default would reject a conformant request object part-way through
// that window, so the profile has to publish the number.
func TestMaxRequestObjectAge(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   profile.Profile
		want time.Duration
	}{
		{"fapi2-baseline", profile.FAPI2Baseline, 60 * time.Minute},
		{"fapi2-message-signing", profile.FAPI2MessageSigning, 60 * time.Minute},
		{"fapi-ciba", profile.FAPICIBA, 60 * time.Minute},
		{"baseline", profile.Baseline, 0},
		{"zero", profile.Profile(0), 0},
		{"unknown", profile.Profile(99), 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := profile.MaxRequestObjectAge(tc.in)
			if got != tc.want {
				t.Errorf("MaxRequestObjectAge(%s) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestAllowedClientAuthMethods(t *testing.T) {
	t.Parallel()

	// The RFC 8705 §2 mTLS methods FAPI 2.0 §3.1.3 also permits are
	// deliberately absent: the OP does not implement them, so listing
	// them would hand callers a seed value no client could use.
	fapi2Allowed := []string{"private_key_jwt"}

	cases := []struct {
		name string
		in   profile.Profile
		want []string
	}{
		{"fapi2-baseline", profile.FAPI2Baseline, fapi2Allowed},
		{"fapi2-message-signing", profile.FAPI2MessageSigning, fapi2Allowed},
		{"fapi-ciba", profile.FAPICIBA, fapi2Allowed},
		{"baseline", profile.Baseline, nil},
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

func TestRequiresNonce(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   profile.Profile
		want bool
	}{
		{"baseline", profile.Baseline, false},
		{"fapi2-baseline", profile.FAPI2Baseline, false},
		{"fapi2-message-signing", profile.FAPI2MessageSigning, false},
		{"fapi-ciba", profile.FAPICIBA, false},
		{"zero", profile.Profile(0), false},
		{"unknown", profile.Profile(99), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := profile.RequiresNonce(tc.in); got != tc.want {
				t.Errorf("RequiresNonce(%s) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestRequiresStateOrNonce(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   profile.Profile
		want bool
	}{
		{"baseline", profile.Baseline, false},
		{"fapi2-baseline", profile.FAPI2Baseline, true},
		{"fapi2-message-signing", profile.FAPI2MessageSigning, true},
		{"fapi-ciba", profile.FAPICIBA, false},
		{"zero", profile.Profile(0), false},
		{"unknown", profile.Profile(99), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := profile.RequiresStateOrNonce(tc.in); got != tc.want {
				t.Errorf("RequiresStateOrNonce(%s) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestRequiresPAR(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   profile.Profile
		want bool
	}{
		{"baseline", profile.Baseline, false},
		{"fapi2-baseline", profile.FAPI2Baseline, true},
		{"fapi2-message-signing", profile.FAPI2MessageSigning, true},
		{"fapi-ciba", profile.FAPICIBA, false},
		{"zero", profile.Profile(0), false},
		{"unknown", profile.Profile(99), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := profile.RequiresPAR(tc.in); got != tc.want {
				t.Errorf("RequiresPAR(%s) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
