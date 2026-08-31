package op

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/profile"
)

// TestEffectiveRefreshGrace_FAPI2KeepsTheDefaultWindow pins the
// resolution [New] hands the token endpoint for a FAPI 2.0 deployment
// that does not set the option: the ordinary default, not a strict zero.
//
// Narrowing it to zero here is the one thing this function must not do.
// A deployment that declares the profile and configures nothing else
// would then have no window at all, and the suite's
// fapi2-security-profile-id2-refresh-token module redeems the rotated
// predecessor a second time and requires a 200 — the retry the window
// exists to absorb (RFC 9700 §2.2.2). A profile the OP cannot be
// certified under is not a stricter profile, it is a broken one.
//
// The same value is the ceiling [config.validateProfile] enforces on an
// explicit window under the profile, so no FAPI 2.0 configuration
// resolves to a wider one than this.
//
// The replay defence that does apply unconditionally is the chain-wide
// cascade, which no profile setting can switch off.
func TestEffectiveRefreshGrace_FAPI2KeepsTheDefaultWindow(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		profiles []profile.Profile
		want     time.Duration
	}{
		{
			name:     "FAPI 2.0 Baseline with the option absent",
			profiles: []profile.Profile{profile.FAPI2Baseline},
			want:     0,
		},
		{
			name:     "FAPI 2.0 Message Signing with the option absent",
			profiles: []profile.Profile{profile.FAPI2MessageSigning},
			want:     0,
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
// pins that an embedder who asks for a window gets it, and that an
// explicit zero stays distinguishable from an absent option — the
// sentinel is what lets the exchanger tell "the embedder said zero"
// from "the embedder said nothing".
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
