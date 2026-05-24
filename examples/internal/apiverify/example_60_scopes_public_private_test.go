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
