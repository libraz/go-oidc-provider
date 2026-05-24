//go:build apiverify

package apiverify

import "testing"

// 31 self-verifies the RFC 8628 device authorization grant in-process
// before driving the CLI flow; the "✓ self-verify" marker is the contract.
func TestExample31DeviceCodeCLI(t *testing.T) {
	runSelfVerify(t, "../../31-device-code-cli")
}
