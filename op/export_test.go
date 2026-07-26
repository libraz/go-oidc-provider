package op

import (
	"io"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
)

// WithInMemoryDPoPNonceRandForTest re-exports the unexported test seam
// that swaps the entropy source on an [InMemoryDPoPNonceSource]. The
// helper exists exclusively for the op_test package so the
// rotation-failure path can be exercised with a faulty [io.Reader]
// without globally swapping [crypto/rand.Reader]. Keeping the
// production option unexported preserves the minimal public surface
// while still letting external tests inject a deterministic source.
func WithInMemoryDPoPNonceRandForTest(r io.Reader) InMemoryDPoPNonceOption {
	return withInMemoryDPoPNonceRand(r)
}

// WithInMemoryDPoPNonceTicksForTest re-exports the unexported test seam
// that drives rotation from a caller-supplied channel instead of a real
// ticker, so a test that asserts on the state around one rotation gets
// exactly one and never races a second.
func WithInMemoryDPoPNonceTicksForTest(ticks <-chan time.Time) InMemoryDPoPNonceOption {
	return withInMemoryDPoPNonceTicks(ticks)
}

// ValidateProfileFeatureSetForTest exercises [config.validateProfile]
// with an arbitrary feature set so the add-only invariant ("a
// profile whose required features are missing must be rejected by
// validate") can be tested through the unexported path. The public
// [WithProfile] option auto-enables every required flag, so this
// helper is the only way for an external test to build the
// "profile present, required flag absent" combination — the case the
// validator's add-only check defends against.
func ValidateProfileFeatureSetForTest(p profile.Profile, features []feature.Flag) error {
	c := &config{
		profiles: []profile.Profile{p},
		features: features,
	}
	enabled := make(map[feature.Flag]struct{}, len(features))
	for _, f := range features {
		enabled[f] = struct{}{}
	}
	return c.validateProfile(p, enabled)
}

// FormatForAudienceForTest applies the supplied [Option] values to a
// fresh [config] and returns the access-token format the OP would
// pick for the given RFC 8707 resource indicator. The helper exists
// so external (op_test) tests can pin the
// [WithAccessTokenFormat] / [WithAccessTokenFormatPerAudience]
// resolution without exposing the unexported lookup. Failures during
// option application surface as t.Fatalf so the test reads as a
// straight assertion on the resolved format.
func FormatForAudienceForTest(tb testing.TB, opts []Option, resource string) AccessTokenFormat {
	tb.Helper()
	c, err := newConfig(opts)
	if err != nil {
		tb.Fatalf("FormatForAudienceForTest: newConfig: %v", err)
	}
	return c.formatForAudience(resource)
}
