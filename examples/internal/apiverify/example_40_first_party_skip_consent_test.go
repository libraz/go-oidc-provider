//go:build apiverify

package apiverify

import "testing"

// 40's deliverable is the consent skip, which the OP can only apply once the
// user is authenticated. The API smoke asserts the first-party client reaches
// the login interaction; the skip that follows it is a browser case.
func TestExample40FirstPartySkipConsent(t *testing.T) {
	runAuthorizeInteraction(t, "../../40-first-party-skip-consent", "http://127.0.0.1:8080",
		authorizeParams("first-party-app", "https://app.example.com/callback", "openid profile email"),
		[]string{`name="password"`})
}
