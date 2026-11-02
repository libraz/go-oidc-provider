package jose_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

// Every advertised name must parse, and the list must cover exactly the
// algorithms IsAllowed admits, so discovery cannot drift from verification.
func TestAllowedAlgorithmNames_MatchesIsAllowed(t *testing.T) {
	t.Parallel()
	names := jose.AllowedAlgorithmNames()
	for _, n := range names {
		if _, ok := jose.ParseAlgorithm(n); !ok {
			t.Errorf("advertised %q is not allowed", n)
		}
	}
	for _, a := range []jose.Algorithm{jose.AlgRS256, jose.AlgPS256, jose.AlgES256, jose.AlgEdDSA} {
		found := false
		for _, n := range names {
			found = found || n == string(a)
		}
		if a.IsAllowed() != found {
			t.Errorf("%q: IsAllowed=%v, advertised=%v", a, a.IsAllowed(), found)
		}
	}
	names[0] = "mutated"
	if jose.AllowedAlgorithmNames()[0] == "mutated" {
		t.Error("AllowedAlgorithmNames returned a shared slice")
	}
}
