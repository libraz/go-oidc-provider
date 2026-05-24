//go:build apiverify

package apiverify

import "testing"

func TestExample60ScopesPublicPrivate(t *testing.T) {
	runDiscovery(t, "../../60-scopes-public-private", "http://127.0.0.1:8080")
}
