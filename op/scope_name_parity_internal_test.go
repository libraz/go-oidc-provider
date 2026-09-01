package op

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/oidcscope"
)

// TestScopeNameParity pins the public scope vocabulary to the strings
// the OP actually matches on.
//
// The six ScopeName constants are what an embedder writes; the values
// that decide behaviour live in internal/oidcscope, because the packages
// that consume them are imported by this one and cannot import it back.
// The duplication is deliberate and has always been documented — but
// nothing compared the two, so a rename on either side would have left
// discovery advertising one scope while the claim projection released
// another, with every gate green.
//
// Adding a standard scope means adding a row here. That is the point:
// the pair is the contract, and a new member of it needs the same
// guarantee as the six that came before.
func TestScopeNameParity(t *testing.T) {
	t.Parallel()

	cases := []struct {
		public   ScopeName
		internal string
		what     string
	}{
		{ScopeNameOpenID, oidcscope.ScopeOpenID, "drives id_token issuance"},
		{ScopeNameProfile, oidcscope.ScopeProfile, "releases the profile claim group"},
		{ScopeNameEmail, oidcscope.ScopeEmail, "releases email and email_verified"},
		{ScopeNameAddress, oidcscope.ScopeAddress, "releases the address claim group"},
		{ScopeNamePhone, oidcscope.ScopePhone, "releases the phone claim group"},
		{ScopeNameOfflineAccess, oidcscope.ScopeOfflineAccess, "gates the offline TTL bucket"},
	}

	for _, c := range cases {
		if string(c.public) != c.internal {
			t.Errorf("public vocabulary %q and the value the OP matches on (%q) disagree; the scope that %s "+
				"would be advertised under one name and honoured under another",
				string(c.public), c.internal, c.what)
		}
	}

	// standardScopeNames is what the discovery document and the default
	// registration are built from. A constant missing from it is a scope
	// the OP declares and never advertises.
	if len(cases) != len(standardScopeNames) {
		t.Fatalf("this test pins %d scope names but standardScopeNames lists %d; "+
			"a standard scope is registered without a parity row, or the reverse",
			len(cases), len(standardScopeNames))
	}
	for i, c := range cases {
		if standardScopeNames[i] != string(c.public) {
			t.Errorf("standardScopeNames[%d]=%q, want %q", i, standardScopeNames[i], string(c.public))
		}
	}
}
