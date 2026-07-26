//go:build browserverify

package browserverify

import "testing"

// 27-durable-mfa-store runs the same password + RFC 6238 TOTP login as
// 20-mfa-totp, but the factor stores come from the SQL adapter sharing
// one *sql.DB with the core tables rather than from the in-memory
// reference, and the cross-factor lockout counter is wired to the same
// database. The browser gate proves the durable stores serve a live
// login (amr must stamp "otp"); the example's own store_test.go proves
// the enrolment and the counter survive a process restart, which a
// single round-trip cannot express.
func TestExample27DurableMFAStore(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:        "../../27-durable-mfa-store",
		username:   "demo",
		password:   "demo",
		wantSub:    "demo-user",
		wantClaims: []string{`"otp"`},
		spa:        true,
		totp:       true,
	})
}
