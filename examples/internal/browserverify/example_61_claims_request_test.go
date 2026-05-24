//go:build browserverify

package browserverify

import "testing"

// 61's whole point is the OIDC Core §5.5 "claims" request: it asks for
// email as essential, so that claim must land in the ID Token rendered on
// /me.
func TestExample61ClaimsRequest(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:        "../../61-claims-request",
		username:   "demo",
		password:   "demo",
		wantSub:    "demo-user",
		wantClaims: []string{`"email": "demo@example.com"`},
	})
}
