package op

import "testing"

// A reason keyed by a label the manifest does not declare would silently
// drop that substore's nil check.
func TestStoreCapabilityReasonsNameManifestRows(t *testing.T) {
	t.Parallel()
	labels := make(map[string]bool, len(storeTableManifest))
	for _, row := range storeTableManifest {
		labels[row.label] = true
	}
	for label := range storeCapabilityReasons {
		if !labels[label] {
			t.Errorf("storeCapabilityReasons[%q] names no storeTableManifest row", label)
		}
	}
}
