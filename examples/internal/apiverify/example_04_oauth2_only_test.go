//go:build apiverify

package apiverify

import "testing"

func TestExample04OAuth2Only(t *testing.T) {
	runDiscovery(t, "../../04-oauth2-only", "http://127.0.0.1:8080")
}
