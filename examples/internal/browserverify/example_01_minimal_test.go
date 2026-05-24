//go:build browserverify

package browserverify

import "testing"

func TestExample01Minimal(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:      "../../01-minimal",
		username: "demo",
		password: "demo",
		wantSub:  "demo-user",
	})
}
