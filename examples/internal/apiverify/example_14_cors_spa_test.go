//go:build apiverify

package apiverify

import "testing"

// 14-cors-spa's deliverable is the CORS allowlist: the SPA's redirect_uri
// origin and an explicit admin origin (op.WithCORSOrigins) are allowed,
// everything else is denied. The preflight smoke proves the allowlist is
// enforced at the token endpoint — the example's whole point.
func TestExample14CORSSPA(t *testing.T) {
	runCORSPreflight(t, "../../14-cors-spa", "http://127.0.0.1:8080",
		[]string{"https://spa.example.com", "https://admin.example.com"},
		"https://evil.example.com")
}
