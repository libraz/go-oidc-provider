package tokens_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/tokens"
)

func TestIsIDTokenReservedClaim_MatchesReservedSet(t *testing.T) {
	t.Parallel()
	for name := range tokens.IDTokenReservedClaims() {
		if !tokens.IsIDTokenReservedClaim(name) {
			t.Fatalf("IsIDTokenReservedClaim(%q) = false for a reserved claim", name)
		}
	}
	if tokens.IsIDTokenReservedClaim("email") {
		t.Fatal(`IsIDTokenReservedClaim("email") = true`)
	}
}
