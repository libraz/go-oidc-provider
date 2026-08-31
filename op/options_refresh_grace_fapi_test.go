package op_test

import (
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
)

// fapi2Profiles are the two profiles whose refresh-grace bound
// [op.WithRefreshGracePeriod]'s godoc describes. FAPI-CIBA is
// deliberately absent: it is not part of the FAPI 2.0 family the
// option layer gates on.
var fapi2Profiles = []profile.Profile{profile.FAPI2Baseline, profile.FAPI2MessageSigning}

// assertResolvedGrace reads the refresh grace window out of the
// startup profile record. That field is the projection of the same
// resolution the router hands the token endpoint as
// RefreshTokenGraceTTL, so asserting on it drives the whole
// profile-to-endpoint wiring rather than the option struct alone.
func assertResolvedGrace(t *testing.T, rec startupRecord, want time.Duration) {
	t.Helper()

	raw, ok := rec.Extras["refresh_grace_period_seconds"]
	if !ok {
		t.Fatalf("refresh_grace_period_seconds missing from the startup record")
	}
	got, ok := raw.(float64)
	if !ok {
		t.Fatalf("refresh_grace_period_seconds = %v (%T), want a number", raw, raw)
	}
	if time.Duration(got)*time.Second != want {
		t.Errorf("resolved refresh grace = %vs, want %v", got, want)
	}
}

// TestWithRefreshGracePeriod_FAPI2AcceptsStricterWindow pins the
// direction the profile bound runs in: a FAPI 2.0 embedder narrowing
// the replay window below the library default gets the window it
// asked for. Rejecting it would leave that embedder on the wider
// inherited default, which is the opposite of what declaring the
// profile is for.
func TestWithRefreshGracePeriod_FAPI2AcceptsStricterWindow(t *testing.T) {
	t.Parallel()

	for _, p := range fapi2Profiles {
		t.Run(p.String(), func(t *testing.T) {
			t.Parallel()
			rec := captureStartupProfile(t,
				op.WithProfile(p),
				op.WithFeature(feature.DPoP),
				op.WithDPoPNonceSource(stubDPoPNonceSource{}),
				op.WithRefreshGracePeriod(5*time.Second),
			)
			assertResolvedGrace(t, rec, 5*time.Second)
		})
	}
}

// TestWithRefreshGracePeriod_FAPI2AcceptsZero confirms the strictest
// end of the accepted range still constructs: explicitly disabling
// the window is the no-replay-tolerance posture FAPI 2.0 §3.1.7
// argues for, and it must remain expressible.
func TestWithRefreshGracePeriod_FAPI2AcceptsZero(t *testing.T) {
	t.Parallel()

	rec := captureStartupProfile(t,
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
		op.WithDPoPNonceSource(stubDPoPNonceSource{}),
		op.WithRefreshGracePeriod(0),
	)
	assertResolvedGrace(t, rec, 0)
}

// TestWithRefreshGracePeriod_FAPI2AcceptsTheDefaultVerbatim covers
// the boundary itself: the cap is inclusive, so restating the
// library default alongside the profile is a valid configuration
// rather than an off-by-one rejection.
func TestWithRefreshGracePeriod_FAPI2AcceptsTheDefaultVerbatim(t *testing.T) {
	t.Parallel()

	rec := captureStartupProfile(t,
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
		op.WithDPoPNonceSource(stubDPoPNonceSource{}),
		op.WithRefreshGracePeriod(refresh.GraceTTLDefault),
	)
	assertResolvedGrace(t, rec, refresh.GraceTTLDefault)
}

// TestWithRefreshGracePeriod_FAPI2InheritsTheDefaultWindow pins the
// resolution a FAPI 2.0 deployment gets when it configures nothing.
// The inherited window is what the conformance suite's refresh-token
// module needs — it redeems the rotated predecessor a second time and
// requires a 200 — so this value is also the ceiling the gate above
// enforces.
func TestWithRefreshGracePeriod_FAPI2InheritsTheDefaultWindow(t *testing.T) {
	t.Parallel()

	for _, p := range fapi2Profiles {
		t.Run(p.String(), func(t *testing.T) {
			t.Parallel()
			rec := captureStartupProfile(t,
				op.WithProfile(p),
				op.WithFeature(feature.DPoP),
				op.WithDPoPNonceSource(stubDPoPNonceSource{}),
			)
			assertResolvedGrace(t, rec, refresh.GraceTTLDefault)
		})
	}
}

// TestWithRefreshGracePeriod_FAPI2RejectsWiderThanDefault pins the
// half of the bound that still bites: a window above the one the
// profile itself resolves to widens the replay tolerance beyond what
// an unconfigured FAPI 2.0 deployment runs, and fails construction
// rather than starting with it.
func TestWithRefreshGracePeriod_FAPI2RejectsWiderThanDefault(t *testing.T) {
	t.Parallel()

	for _, p := range fapi2Profiles {
		t.Run(p.String(), func(t *testing.T) {
			t.Parallel()
			opts := append(validBaseOptsWithInmem(t),
				op.WithProfile(p),
				op.WithFeature(feature.DPoP),
				op.WithDPoPNonceSource(stubDPoPNonceSource{}),
				op.WithRefreshGracePeriod(refresh.GraceTTLDefault+time.Second),
			)
			_, err := op.New(opts...)
			if err == nil {
				t.Fatalf("expected construction error for %s + a wider-than-default refresh grace, got nil", p)
			}
			if !op.IsServerError(err) {
				t.Errorf("expected a server-side configuration error, got %v", err)
			}
			if !strings.Contains(err.Error(), "WithRefreshGracePeriod") {
				t.Errorf("err = %v, want it to mention WithRefreshGracePeriod", err)
			}
			// The message has to name the value the OP would actually
			// apply; a compliance reviewer reading it otherwise cannot
			// tell which window the deployment ends up on.
			if !strings.Contains(err.Error(), refresh.GraceTTLDefault.String()) {
				t.Errorf("err = %v, want it to name the %v cap", err, refresh.GraceTTLDefault)
			}
		})
	}
}

// TestWithRefreshGracePeriod_NonFAPIProfileAllowsWiderWindow
// confirms the gate is FAPI-2.0-family specific: FAPI-CIBA is outside
// the classification [op.WithRefreshGracePeriod]'s godoc names, so a
// window well above the library default constructs cleanly and
// reaches the endpoint unchanged.
func TestWithRefreshGracePeriod_NonFAPIProfileAllowsWiderWindow(t *testing.T) {
	t.Parallel()

	rec := captureStartupProfile(t,
		op.WithCIBA(op.WithCIBAHintResolver(stubCIBAHintResolver{})),
		op.WithProfile(profile.FAPICIBA),
		op.WithFeature(feature.DPoP),
		op.WithDPoPNonceSource(stubDPoPNonceSource{}),
		op.WithRefreshGracePeriod(2*refresh.GraceTTLDefault),
	)
	assertResolvedGrace(t, rec, 2*refresh.GraceTTLDefault)
}
