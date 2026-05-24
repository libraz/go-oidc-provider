//go:build apiverify

package apiverify

import "testing"

func TestExample16CustomInteraction(t *testing.T) {
	runDiscovery(t, "../../16-custom-interaction", "http://127.0.0.1:8080")
}
