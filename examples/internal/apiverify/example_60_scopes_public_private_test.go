//go:build apiverify

package apiverify

import "testing"

// 60's deliverable is the public/internal scope split: public scopes appear
// in scopes_supported, the internal-flagged "internal:audit" scope is
// accepted at /authorize but never advertised. Assert the document carries
// the public surface but hides the internal scope.
func TestExample60ScopesPublicPrivate(t *testing.T) {
	runDiscoveryAssert(t, "../../60-scopes-public-private", "http://127.0.0.1:8080",
		[]string{`"scopes_supported"`}, []string{"internal:audit"})
}

// Hiding a scope from discovery is only half the claim; the other half
// is that the flow still runs. This probe drives an authorization
// request carrying the unadvertised scope and asserts it reaches a
// login prompt rather than being rejected for a scope the document
// deliberately omits.
func TestExample60ScopesPublicPrivate_InternalScopeStillAuthorizes(t *testing.T) {
	runAuthorizeInteraction(t, "../../60-scopes-public-private", "http://127.0.0.1:8080",
		authorizeParams("demo-rp", "http://localhost:5173/callback", "openid profile internal:audit"),
		[]string{`name="password"`})
}
