//go:build browserverify

package browserverify

import "testing"

func TestExample08CompositeHotCold(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:      "../../08-composite-hot-cold",
		username: "demo",
		password: "demo",
		wantSub:  "demo-user",
	})
}
