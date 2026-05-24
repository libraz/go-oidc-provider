//go:build browserverify

package browserverify

import "testing"

// 41 has no browser-visible distinctive claim: the RP cannot log in unless
// its startup self-registration (RFC 7591) succeeded, so a passing
// round-trip already proves the dynamic-registration path.
func TestExample41DynamicRegistration(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:      "../../41-dynamic-registration",
		username: "demo",
		password: "demo",
		wantSub:  "demo-user",
	})
}
