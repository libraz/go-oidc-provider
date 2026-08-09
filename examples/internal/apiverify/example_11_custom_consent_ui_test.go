//go:build apiverify

package apiverify

import "testing"

// 11's deliverable is the consent template, which a user only reaches
// after signing in. Asserting the login prompt renders covers the step
// that has to work before consent can be reached at all.
func TestExample11CustomConsentUI(t *testing.T) {
	runAuthorizeInteraction(t, "../../11-custom-consent-ui", "http://127.0.0.1:8080",
		authorizeParams("demo-rp", "http://localhost:8081/callback", "openid profile email"),
		[]string{`name="password"`})
}
