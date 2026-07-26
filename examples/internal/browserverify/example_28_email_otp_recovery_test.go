//go:build browserverify

package browserverify

import "testing"

// 28-email-otp-recovery gates every login on a code mailed to the address
// bound to the subject's "email" claim. The demo delivery hook prints the
// code instead of sending it, which is the only reason this flow can be
// driven at all — the harness reads the code out of the example's log the
// way a user would read it out of an inbox.
//
// "otp" in amr is the assertion that matters: the mailed code is a
// possession factor, so a login that produced it must stamp the same
// value a TOTP login does. The address bound to the claim is what the
// step dispatches to; submitting a different one looks identical to the
// user and mails nothing, so a round-trip that reached /me proves the
// match was made rather than skipped.
func TestExample28EmailOTP(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:          "../../28-email-otp-recovery",
		username:     "demo",
		password:     "demo",
		wantSub:      "demo-user",
		wantClaims:   []string{`"otp"`},
		spa:          true,
		emailAddress: "demo@example.com",
	})
}

// TestExample28RecoveryFallback drives the path the example exists to
// show: the mailed code never arrives, so after two rejected attempts the
// flow stops asking for it and demands a code from the printed sheet
// instead. The rejections are what carry the story — the fallback is a
// Decider reading FailedAttempts, and a run that reached /me without
// failing anything would have taken the ordinary e-mail path and asserted
// nothing about the fallback.
//
// The recovery code comes from the startup banner, which is the enrolment
// half: op/recoverykit mints the batch and the example prints it once,
// because a code the user has never seen is not a factor.
func TestExample28RecoveryFallback(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:          "../../28-email-otp-recovery",
		username:     "demo",
		password:     "demo",
		wantSub:      "demo-user",
		wantClaims:   []string{`"otp"`},
		spa:          true,
		emailAddress: "demo@example.com",
		recovery:     true,
		failCode:     2,
	})
}
