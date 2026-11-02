package jose

import "testing"

// Every advertised name must parse, and the list must cover exactly the
// algorithms IsAllowed admits, so discovery cannot drift from verification.
func TestAllowedAlgorithmNames_MatchesIsAllowed(t *testing.T) {
	names := AllowedAlgorithmNames()
	for _, n := range names {
		if _, ok := ParseAlgorithm(n); !ok {
			t.Errorf("advertised %q is not allowed", n)
		}
	}
	for _, a := range []Algorithm{AlgRS256, AlgPS256, AlgES256, AlgEdDSA} {
		found := false
		for _, n := range names {
			found = found || n == string(a)
		}
		if a.IsAllowed() != found {
			t.Errorf("%q: IsAllowed=%v, advertised=%v", a, a.IsAllowed(), found)
		}
	}
	names[0] = "mutated"
	if AllowedAlgorithmNames()[0] == "mutated" {
		t.Error("AllowedAlgorithmNames returned a shared slice")
	}
}
