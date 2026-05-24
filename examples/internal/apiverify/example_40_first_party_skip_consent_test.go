//go:build apiverify

package apiverify

import "testing"

func TestExample40FirstPartySkipConsent(t *testing.T) {
	runDiscovery(t, "../../40-first-party-skip-consent", "http://127.0.0.1:8080")
}
