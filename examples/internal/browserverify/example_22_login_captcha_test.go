//go:build browserverify

package browserverify

import "testing"

// 22-login-captcha injects a captcha after three consecutive password
// failures (op.RuleAfterFailedAttempts). The driver submits a wrong
// password three times to trip the rule, clears the captcha (the stub
// verifier accepts any non-empty token), then logs in correctly. Reaching
// /me proves the failure-counting + captcha gate let a genuine user
// through; iss/sub characterise the result.
func TestExample22LoginCaptcha(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:          "../../22-login-captcha",
		username:     "demo",
		password:     "demo",
		wantSub:      "demo-user",
		spa:          true,
		failPassword: 3,
	})
}
