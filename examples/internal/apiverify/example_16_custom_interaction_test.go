//go:build apiverify

package apiverify

import "testing"

// 16 replaces the interaction driver wholesale, so the prompt the OP
// hands back is the example's own rendering rather than the bundled
// one. Following the hand-off is the only way to see it, and the shape
// is itself the assertion: this driver answers in JSON, so the password
// step arrives as a typed step with named inputs rather than as a form.
func TestExample16CustomInteraction(t *testing.T) {
	runAuthorizeInteraction(t, "../../16-custom-interaction", "http://127.0.0.1:8080",
		authorizeParams("demo-spa", "http://localhost:5173/callback", "openid profile"),
		[]string{`"type":"auth.password"`, `"Name":"password"`})
}
