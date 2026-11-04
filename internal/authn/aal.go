package authn

import opauthn "github.com/libraz/go-oidc-provider/op/authn"

// AAL enumerates the Authenticator Assurance Levels the library tracks for
// a completed authentication; declared in
// [github.com/libraz/go-oidc-provider/op/authn].
type AAL = opauthn.AAL

// AAL levels.
const (
	AAL0 = opauthn.AAL0
	AAL1 = opauthn.AAL1
	AAL2 = opauthn.AAL2
	AAL3 = opauthn.AAL3
)

// AALFromACRURI is the inverse of [AAL.ACRURI]: it returns the level whose
// canonical URI is uri, and [AAL0] for any other string. A session records
// the canonical URI of the level it reached, so this recovers that level
// without trusting an acr string a relying party chose.
func AALFromACRURI(uri string) AAL {
	for _, l := range []AAL{AAL1, AAL2, AAL3} {
		if uri == l.ACRURI() {
			return l
		}
	}
	return AAL0
}
