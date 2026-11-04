//go:build apiverify

package apiverify

import "testing"

// 55 runs its own mutual-TLS client against the OP through the in-process
// TLS proxy and prints the self-verify marker only when the token it got was
// bound to the client certificate (cnf x5t#S256) and the same request
// without a certificate was refused. The certificates are generated at start,
// so the example itself is the only party that can present them.
func TestExample55MTLSProxy(t *testing.T) {
	runSelfVerify(t, "../../55-mtls-proxy")
}
