package timex_test

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"
)

// TestTTLDefaults_Values pins each canonical TTL default to its exact
// duration so a silent edit of internal/timex/ttldefaults.go (which
// every caller now consumes) trips a test failure rather than rolling
// out a quiet operational regression.
func TestTTLDefaults_Values(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"RefreshTokenTTLDefault", timex.RefreshTokenTTLDefault, 30 * 24 * time.Hour},
		{"AccessTokenTTLMax", timex.AccessTokenTTLMax, 24 * time.Hour},
		{"RegistrationIATTTLDefault", timex.RegistrationIATTTLDefault, 24 * time.Hour},
		{"SectorURICacheTTLDefault", timex.SectorURICacheTTLDefault, 24 * time.Hour},
		{"SessionIdleTTLDefault", timex.SessionIdleTTLDefault, 14 * 24 * time.Hour},
		{"SessionAbsoluteTTLDefault", timex.SessionAbsoluteTTLDefault, 30 * 24 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.got != tc.want {
				t.Fatalf("%s = %v, want %v", tc.name, tc.got, tc.want)
			}
		})
	}
}
