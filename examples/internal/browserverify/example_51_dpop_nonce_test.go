//go:build browserverify

package browserverify

import "testing"

// 51 is the same DPoP binding as 03, reached only after the OP's
// use_dpop_nonce challenge and rpkit's nonce retry. Assert the bound token
// type and cnf jkt rpkit echoes onto /me.
func TestExample51DPoPNonce(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:        "../../51-dpop-nonce",
		username:   "demo",
		password:   "demo",
		wantSub:    "demo-user",
		wantClaims: []string{`"_token_type": "DPoP"`, `"_access_token_cnf_jkt"`},
	})
}
