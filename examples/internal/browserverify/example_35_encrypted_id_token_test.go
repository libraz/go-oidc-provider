//go:build browserverify

package browserverify

import "testing"

// 35 has no browser-visible distinctive claim: the RP only reaches /me if
// it decrypted the JWE-wrapped ID Token, so a passing round-trip already
// proves the encryption path. iss/sub fully characterise it.
func TestExample35EncryptedIDToken(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:      "../../35-encrypted-id-token",
		username: "demo",
		password: "demo",
		wantSub:  "demo-user",
	})
}
