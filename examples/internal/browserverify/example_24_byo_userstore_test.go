//go:build browserverify

package browserverify

import "testing"

// 24 projects an embedder-owned members table onto OIDC, so the subject is
// the member id (mem-0001), not the login name — that mapping is the value
// the example demonstrates and the sub assertion already pins it.
func TestExample24BYOUserstore(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:      "../../24-byo-userstore",
		username: "demo@example.test",
		password: "demo",
		wantSub:  "mem-0001",
	})
}
