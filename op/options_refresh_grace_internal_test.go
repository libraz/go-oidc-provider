package op

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/profile"
)

// TestEffectiveRefreshGrace_FAPI2DefaultsToStrictZero pins the
// resolution [New] hands the token endpoint, which is where the FAPI
// 2.0 §3.1.7 guarantee is actually decided.
//
// The check that already existed refused an explicit non-zero grace
// under a FAPI 2.0 profile. On its own that honoured the profile only
// for the embedder who asked for the forbidden thing out loud: leaving
// the option off resolved to 0, which the exchanger reads as "use the
// default" — a 60-second replay-tolerant window — so the profile was
// silently violated by the configuration every FAPI deployment
// actually writes.
//
// The negative sentinel is what distinguishes "the embedder said zero"
// from "the embedder said nothing"; the exchanger's own tests cover
// what it does with each.
func TestEffectiveRefreshGrace_FAPI2DefaultsToStrictZero(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		profiles []profile.Profile
		want     time.Duration
	}{
		{
			name:     "FAPI 2.0 Baseline with the option absent",
			profiles: []profile.Profile{profile.FAPI2Baseline},
			want:     -1,
		},
		{
			name:     "FAPI 2.0 Message Signing with the option absent",
			profiles: []profile.Profile{profile.FAPI2MessageSigning},
			want:     -1,
		},
		{
			name:     "no profile declared",
			profiles: nil,
			want:     0,
		},
		{
			name:     "Baseline, which places no constraint here",
			profiles: []profile.Profile{profile.Baseline},
			want:     0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := &config{profiles: tc.profiles}
			if got := c.effectiveRefreshGrace(); got != tc.want {
				t.Errorf("effectiveRefreshGrace()=%v want %v", got, tc.want)
			}
		})
	}
}

// TestEffectiveRefreshGrace_ExplicitValueSurvivesTheProfileDefault
// pins that the profile default only fills a gap. An embedder running
// without a FAPI profile who asks for a window still gets it, and an
// explicit zero is still distinguishable from an absent option.
func TestEffectiveRefreshGrace_ExplicitValueSurvivesTheProfileDefault(t *testing.T) {
	t.Parallel()

	explicit := &config{refreshGracePeriodSet: true, refreshGracePeriod: 30 * time.Second}
	if got := explicit.effectiveRefreshGrace(); got != 30*time.Second {
		t.Errorf("explicit window: got %v want 30s", got)
	}

	zero := &config{refreshGracePeriodSet: true, refreshGracePeriodIsZero: true}
	if got := zero.effectiveRefreshGrace(); got != -1 {
		t.Errorf("explicit zero: got %v want the explicit-zero sentinel", got)
	}
}
