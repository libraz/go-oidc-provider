package op_test

import (
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
)

// TestWithRefreshGracePeriod_FAPI2RejectsNonZero pins the FAPI 2.0
// §3.1.7 enforcement [op.WithRefreshGracePeriod]'s godoc
// promises: a FAPI2Baseline / FAPI2MessageSigning deployment MUST NOT
// tolerate a replay window on a stolen/replayed refresh token, so a
// non-zero grace period paired with either profile fails [op.New]
// with a construction error rather than silently starting with an
// open replay window.
func TestWithRefreshGracePeriod_FAPI2RejectsNonZero(t *testing.T) {
	t.Parallel()

	for _, p := range []profile.Profile{profile.FAPI2Baseline, profile.FAPI2MessageSigning} {
		t.Run(p.String(), func(t *testing.T) {
			t.Parallel()
			opts := append(validBaseOptsWithInmem(t),
				op.WithProfile(p),
				op.WithFeature(feature.DPoP),
				op.WithDPoPNonceSource(stubDPoPNonceSource{}),
				op.WithRefreshGracePeriod(60*time.Second),
			)
			_, err := op.New(opts...)
			if err == nil {
				t.Fatalf("expected construction error for %s + non-zero refresh grace, got nil", p)
			}
			if !op.IsServerError(err) {
				t.Errorf("expected a server-side configuration error, got %v", err)
			}
			if !strings.Contains(err.Error(), "WithRefreshGracePeriod") {
				t.Errorf("err = %v, want it to mention WithRefreshGracePeriod", err)
			}
		})
	}
}

// TestWithRefreshGracePeriod_FAPI2AcceptsZero confirms the companion
// case: explicitly disabling the grace window (WithRefreshGracePeriod(0))
// is accepted under a FAPI 2.0 profile, matching the "no replay
// tolerance" posture the spec mandates.
func TestWithRefreshGracePeriod_FAPI2AcceptsZero(t *testing.T) {
	t.Parallel()

	opts := append(validBaseOptsWithInmem(t),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
		op.WithDPoPNonceSource(stubDPoPNonceSource{}),
		op.WithRefreshGracePeriod(0),
	)
	if _, err := op.New(opts...); err != nil {
		t.Fatalf("WithProfile(FAPI2Baseline) + WithRefreshGracePeriod(0) failed: %v", err)
	}
}

// TestWithRefreshGracePeriod_NonFAPIProfileAllowsNonZero confirms the
// gate is FAPI-2.0-family specific: FAPI-CIBA is not named by
// [op.WithRefreshGracePeriod]'s godoc and [isFAPI2Profile]'s
// classification, so a non-zero grace period alongside FAPICIBA
// still constructs cleanly.
func TestWithRefreshGracePeriod_NonFAPIProfileAllowsNonZero(t *testing.T) {
	t.Parallel()

	opts := append(validBaseOptsWithInmem(t),
		op.WithCIBA(op.WithCIBAHintResolver(stubCIBAHintResolver{})),
		op.WithProfile(profile.FAPICIBA),
		op.WithFeature(feature.DPoP),
		op.WithDPoPNonceSource(stubDPoPNonceSource{}),
		op.WithRefreshGracePeriod(60*time.Second),
	)
	if _, err := op.New(opts...); err != nil {
		t.Fatalf("WithProfile(FAPICIBA) + non-zero refresh grace failed: %v", err)
	}
}
