//go:build browserverify

package browserverify

import "testing"

// 27-durable-mfa-store runs the same password + RFC 6238 TOTP login as
// 20-mfa-totp, but the factor store is a hand-written, SQL-backed
// store.TOTPStore sharing one *sql.DB with the core adapter rather than
// the in-memory reference. The browser gate proves the durable store
// serves a live login (amr must stamp "otp"); the example's own
// store_test.go proves the enrolment survives a process restart, which a
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
