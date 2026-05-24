//go:build browserverify

package browserverify

import "testing"

// 21-risk-based-mfa routes per-risk: the RP's high-risk link requests an
// acr_values the assessor scores High, so the orchestrator schedules both
// TOTP and captcha on top of the password (TOTP first, then captcha, per
// rule order). Driving /login-high exercises the full chain; the amr claim
// must carry "otp" from the risk-triggered TOTP step.
func TestExample21RiskBasedMFA(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:        "../../21-risk-based-mfa",
		username:   "demo",
		password:   "demo",
		wantSub:    "demo-user",
		wantClaims: []string{`"otp"`},
		spa:        true,
		totp:       true,
		loginLink:  `a[href="/login-high"]`,
	})
}
