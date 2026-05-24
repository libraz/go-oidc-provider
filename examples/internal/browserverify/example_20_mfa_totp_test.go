//go:build browserverify

package browserverify

import "testing"

// 20-mfa-totp always requires password + RFC 6238 TOTP at login. The
// harness scrapes the base32 secret from the startup banner, computes the
// live code, and drives the SPA's password → TOTP → consent sequence. The
// amr claim is the distinctive value: a TOTP-gated login must stamp
// "otp" (the orchestrator emits amr=["mfa","otp","pwd"]).
func TestExample20MFATOTP(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:        "../../20-mfa-totp",
		username:   "demo",
		password:   "demo",
		wantSub:    "demo-user",
		wantClaims: []string{`"otp"`},
		spa:        true,
		totp:       true,
	})
}
