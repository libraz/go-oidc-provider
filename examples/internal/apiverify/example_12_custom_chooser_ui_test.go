//go:build apiverify

package apiverify

import "testing"

func TestExample12CustomChooserUI(t *testing.T) {
	runDiscovery(t, "../../12-custom-chooser-ui", "http://127.0.0.1:8080")
}
