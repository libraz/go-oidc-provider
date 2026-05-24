//go:build apiverify

package apiverify

import "testing"

func TestExample11CustomConsentUI(t *testing.T) {
	runDiscovery(t, "../../11-custom-consent-ui", "http://127.0.0.1:8080")
}
