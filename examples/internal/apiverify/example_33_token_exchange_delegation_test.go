//go:build apiverify

package apiverify

import "testing"

// 33 self-verifies an RFC 8693 token exchange with act-chain verification
// in-process before opening its public listener; the "✓ self-verify"
// marker is the contract.
func TestExample33TokenExchangeDelegation(t *testing.T) {
	runSelfVerify(t, "../../33-token-exchange-delegation")
}
