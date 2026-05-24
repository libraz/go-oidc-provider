//go:build apiverify

package apiverify

import "testing"

func TestExample13MultiAccount(t *testing.T) {
	runDiscovery(t, "../../13-multi-account", "http://127.0.0.1:8080")
}
