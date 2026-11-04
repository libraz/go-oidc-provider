//go:build browserverify

package browserverify

import (
	"regexp"
	"testing"
)

// 24 projects an embedder-owned members table onto OIDC, so the subject is
// the opaque random subject column (32 hex digits), not the member_id
// primary key (mem-0001) and not the login name. The assertion pins the
// shape because the value is generated on every run.
func TestExample24BYOUserstore(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:            "../../24-byo-userstore",
		username:       "demo@example.test",
		password:       "demo",
		wantSubPattern: regexp.MustCompile(`[0-9a-f]{32}`),
	})
}
