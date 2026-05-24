//go:build browserverify

package browserverify

import "testing"

// 03-fapi2 drives the same default-HTML login as 01: rpkit performs the
// FAPI 2.0 mechanics (PAR, private_key_jwt, DPoP) server-side, invisible to
// the browser. The DPoP binding is the distinctive value, so assert the
// token type and cnf jkt rpkit echoes onto /me — proving the binding
// survived the round-trip, not just that login succeeded.
func TestExample03FAPI2(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:        "../../03-fapi2",
		username:   "demo",
		password:   "demo",
		wantSub:    "demo-user",
		wantClaims: []string{`"_token_type": "DPoP"`, `"_access_token_cnf_jkt"`},
	})
}
