//go:build browserverify

package browserverify

import "testing"

// 02-bundle is the "everything wired" SPA: a first-party client with a
// mandatory TOTP second factor. The SPA loop drives password → TOTP →
// consent; the amr claim must carry "otp" from the TOTP step.
func TestExample02Bundle(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:        "../../02-bundle",
		username:   "demo",
		password:   "demo",
		wantSub:    "demo-user",
		wantClaims: []string{`"otp"`},
		spa:        true,
		totp:       true,
	})
}
