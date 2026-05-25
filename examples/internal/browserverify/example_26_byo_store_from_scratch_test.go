//go:build browserverify

package browserverify

import "testing"

// 26 backs the OP with a from-scratch store.Store whose tables and columns
// are hand-rolled (vault_* schema). The full login round-trip exercises the
// custom Clients/AuthorizationCodes/Grants/Sessions/Interactions/Users/
// AccessTokens substores; the seeded subject is principal-0001.
func TestExample26BYOStoreFromScratch(t *testing.T) {
	runRoundTrip(t, exampleSpec{
		dir:      "../../26-byo-store-from-scratch",
		username: "demo@example.test",
		password: "demo",
		wantSub:  "principal-0001",
	})
}
