//go:build apiverify

package apiverify

import "testing"

// 04 serves plain OAuth 2.0 alongside OIDC. Its distinctive assertion —
// the oauth-cli client (scope=api:read, no openid) gets an access_token
// but no id_token — needs a full authorization_code round-trip, and
// oauth-cli has no client_credentials grant to shortcut over HTTP. The code
// flow requires browser login + reading the code off a placeholder
// redirect, which is the example-verify skill's browser+network-log job,
// not an HTTP smoke. Here we assert only that the dual-protocol OP boots and
// serves discovery.
func TestExample04OAuth2Only(t *testing.T) {
	runDiscovery(t, "../../04-oauth2-only", "http://127.0.0.1:8080")
}
