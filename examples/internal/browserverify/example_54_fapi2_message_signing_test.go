//go:build browserverify

package browserverify

import "testing"

// 54-fapi2-message-signing drives the same default-HTML login as 03: the
// signed request object, the JARM response and the DPoP nonce loop all run
// server-side between rpkit and the OP. The browser only sees the redirect
// carrying the signed response, so the proof is what rpkit echoes onto /me:
// it reaches /me only after verifying the JARM signature, and the retry flag
// shows the nonce challenge was answered.
func TestExample54FAPI2MessageSigning(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:      "../../54-fapi2-message-signing",
		username: "demo",
		password: "demo",
		wantSub:  "demo-user",
		wantClaims: []string{
			`"_token_type": "DPoP"`,
			`"_access_token_cnf_jkt"`,
			`"_authorization_response": "JARM"`,
			`"_dpop_nonce_retried": true`,
		},
	})
}
