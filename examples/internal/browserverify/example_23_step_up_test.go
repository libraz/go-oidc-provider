//go:build browserverify

package browserverify

import "testing"

// 23-step-up logs in with password only, then the RP's /step-up leg
// requests acr_values=urn:mace:incommon:iap:silver with prompt=login,
// forcing re-authentication plus a TOTP factor (op.RuleACR). The driver
// runs both legs in one session; the stepped-up ID Token's acr claim must
// reflect the silver level the second leg satisfied.
func TestExample23StepUp(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:        "../../23-step-up",
		username:   "demo",
		password:   "demo",
		wantSub:    "demo-user",
		wantClaims: []string{`"acr": "urn:mace:incommon:iap:silver"`},
		spa:        true,
		totp:       true,
		stepUp:     true,
	})
}
