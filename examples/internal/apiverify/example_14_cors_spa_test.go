//go:build apiverify

package apiverify

import "testing"

func TestExample14CORSSPA(t *testing.T) {
	runDiscovery(t, "../../14-cors-spa", "http://127.0.0.1:8080")
}
