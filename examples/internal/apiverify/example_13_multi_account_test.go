//go:build apiverify

package apiverify

import "testing"

// 13 drives the chooser through JSONDriver, so every prompt on the way there
// is a JSON envelope too. Asserting the login prompt comes back as JSON pins
// both halves of the example: the flow reaches an interaction at all, and the
// configured driver — not the bundled HTML one — renders it.
func TestExample13MultiAccount(t *testing.T) {
	runAuthorizeInteraction(t, "../../13-multi-account", "http://127.0.0.1:8080",
		authorizeParams("demo-rp", "http://localhost:8081/callback", "openid profile email"),
		[]string{`"type"`, `"password"`})
}
