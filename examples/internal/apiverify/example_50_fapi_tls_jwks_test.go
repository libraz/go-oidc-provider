//go:build apiverify

package apiverify

import "testing"

// 50 needs FAPI_CERT / FAPI_KEY to serve over TLS; without them it logs the
// skip notice and exits cleanly. The smoke verifies that build + no-cert
// path, which is all that runs in CI without operator-supplied certs.
func TestExample50FAPITLSJWKS(t *testing.T) {
	runExitZero(t, "../../50-fapi-tls-jwks")
}
