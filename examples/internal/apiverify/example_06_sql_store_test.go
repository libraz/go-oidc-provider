//go:build apiverify

package apiverify

import "testing"

// 06 serves its login out of a SQLite-backed user store. Driving the
// authorization request to the password prompt is what exercises that
// store: discovery answers identically whether or not any user can
// actually authenticate.
func TestExample06SQLStore(t *testing.T) {
	runAuthorizeInteraction(t, "../../06-sql-store", "http://127.0.0.1:8080",
		authorizeParams("demo-spa", "https://rp.example.com/cb", "openid profile email"),
		[]string{`name="password"`})
}
