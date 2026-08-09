//go:build apiverify

package apiverify

import "testing"

// 42 delivers logout tokens to a registered RP. The delivery itself
// needs a seeded session, but the session starts here: the probe pins
// that the authorization request reaches a login prompt.
func TestExample42BackChannelLogout(t *testing.T) {
	runAuthorizeInteraction(t, "../../42-back-channel-logout", "http://127.0.0.1:8080",
		authorizeParams("demo-rp", "http://127.0.0.1:5173/callback", "openid profile"),
		[]string{`name="password"`})
}
