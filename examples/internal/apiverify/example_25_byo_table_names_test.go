//go:build apiverify

package apiverify

import "testing"

// 25 renames every OP-internal table. A name the migration created but
// a query does not use surfaces at login, not at construction, so the
// probe has to reach the password prompt to mean anything.
func TestExample25BYOTableNames(t *testing.T) {
	runAuthorizeInteraction(t, "../../25-byo-table-names", "http://127.0.0.1:8080",
		authorizeParams("demo-spa", "https://rp.example.com/cb", "openid profile email"),
		[]string{`name="password"`})
}
