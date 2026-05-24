//go:build apiverify

package apiverify

import "testing"

// 30 runs an in-process round-trip of an embedder-defined grant_type and
// prints a "✓ self-verify" marker before opening its public listener.
func TestExample30CustomGrant(t *testing.T) {
	runSelfVerify(t, "../../30-custom-grant")
}
