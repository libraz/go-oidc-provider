//go:build apiverify

package apiverify

import "testing"

// 12's deliverable is the WithChooserUI template, which only renders once the
// browser holds at least one session. The API smoke covers the step that has
// to work before a chooser can exist at all: /authorize hands off to the OP's
// own login interaction instead of failing the request.
func TestExample12CustomChooserUI(t *testing.T) {
	runAuthorizeInteraction(t, "../../12-custom-chooser-ui", "http://127.0.0.1:8080",
		authorizeParams("demo-rp", "http://localhost:8081/callback", "openid profile email"),
		[]string{`name="password"`})
}
