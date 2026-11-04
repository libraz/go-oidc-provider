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

// fapi2Profiles are the two profiles that do not rotate refresh tokens
// and therefore refuse [op.WithRefreshGracePeriod]. FAPI-CIBA is
// deliberately absent: it keeps rotating.
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

// TestWithRefreshGracePeriod_FAPI2Rejected pins that a profile which
// does not rotate refresh tokens refuses the grace option outright,
// zero included: there is no rotation for a window to absorb, and the
// error says so.
func TestWithRefreshGracePeriod_FAPI2Rejected(t *testing.T) {
	t.Parallel()

	for _, p := range fapi2Profiles {
		for _, grace := range []time.Duration{0, 5 * time.Second, refresh.GraceTTLDefault, 2 * refresh.GraceTTLDefault} {
			t.Run(p.String()+"/"+grace.String(), func(t *testing.T) {
				t.Parallel()
				opts := append(validBaseOptsWithInmem(t),
					op.WithProfile(p),
					op.WithFeature(feature.DPoP),
					op.WithDPoPNonceSource(stubDPoPNonceSource{}),
					op.WithRefreshGracePeriod(grace),
				)
				_, err := op.New(opts...)
				if err == nil {
					t.Fatalf("expected construction error for %s + WithRefreshGracePeriod(%v), got nil", p, grace)
				}
				if !op.IsServerError(err) {
					t.Errorf("expected a server-side configuration error, got %v", err)
				}
				for _, want := range []string{"WithRefreshGracePeriod", "does not rotate refresh tokens"} {
					if !strings.Contains(err.Error(), want) {
						t.Errorf("err = %v, want it to mention %q", err, want)
					}
				}
			})
		}
	}
}

// TestRefreshRotation_FAPI2StartupRecord pins the posture the startup
// record reports for an unconfigured FAPI 2.0 deployment: no rotation,
// and therefore no grace window. Both fields project the same
// resolution the router hands the token endpoint.
func TestRefreshRotation_FAPI2StartupRecord(t *testing.T) {
	t.Parallel()

	for _, p := range fapi2Profiles {
		t.Run(p.String(), func(t *testing.T) {
			t.Parallel()
			rec := captureStartupProfile(t,
				op.WithProfile(p),
				op.WithFeature(feature.DPoP),
				op.WithDPoPNonceSource(stubDPoPNonceSource{}),
			)
			assertResolvedGrace(t, rec, 0)
			assertBool(t, rec, "refresh_rotation", false)
		})
	}
}

// TestWithRefreshGracePeriod_NonFAPIProfileAllowsWiderWindow
// confirms the gate is FAPI-2.0-family specific: FAPI-CIBA rotates, so
// a window well above the library default constructs cleanly and
// reaches the endpoint unchanged.
func TestWithRefreshGracePeriod_NonFAPIProfileAllowsWiderWindow(t *testing.T) {
	t.Parallel()

	rec := captureStartupProfile(t,
		op.WithCIBAGrant(op.CIBAGrant{HintResolver: stubCIBAHintResolver{}}),
		op.WithProfile(profile.FAPICIBA),
		op.WithFeature(feature.DPoP),
		op.WithDPoPNonceSource(stubDPoPNonceSource{}),
		op.WithRefreshGracePeriod(2*refresh.GraceTTLDefault),
	)
	assertResolvedGrace(t, rec, 2*refresh.GraceTTLDefault)
	assertBool(t, rec, "refresh_rotation", true)
}

// TestRefreshRotation_DefaultStartupRecord confirms a deployment without
// a FAPI 2.0 profile keeps rotating with the library default window.
func TestRefreshRotation_DefaultStartupRecord(t *testing.T) {
	t.Parallel()

	rec := captureStartupProfile(t)
	assertResolvedGrace(t, rec, refresh.GraceTTLDefault)
	assertBool(t, rec, "refresh_rotation", true)
}
