//go:build browserverify

package browserverify

import "testing"

// 10-react-login delegates login to a SPA (op.WithSPAUI): the vanilla JS
// bundle renders the password and consent prompts over a JSON contract
// instead of the default HTML forms. iss/sub fully characterise it — the
// distinctive bit is the SPA seam itself, which the spa driver exercises.
func TestExample10ReactLogin(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:      "../../10-react-login",
		username: "demo",
		password: "demo",
		wantSub:  "demo-user",
		spa:      true,
	})
}
