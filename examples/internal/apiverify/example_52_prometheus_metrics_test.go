//go:build apiverify

package apiverify

import "testing"

// 52's deliverable is the embedder-mounted /metrics surface fed by the OP's
// metrics bridge. The library emits oidc_* series only after a business
// event, so the smoke triggers a failing token request first, then asserts
// the /metrics endpoint exposes the oidc_ family.
func TestExample52PrometheusMetrics(t *testing.T) {
	runMetrics(t, "../../52-prometheus-metrics", "http://127.0.0.1:8080")
}

// The oidc_ series describe an OP that serves users, so the smoke also
// pins that a user can start: the authorization request reaches a login
// prompt instead of failing before any business event exists to count.
func TestExample52PrometheusMetrics_AuthorizeReachesLogin(t *testing.T) {
	runAuthorizeInteraction(t, "../../52-prometheus-metrics", "http://127.0.0.1:8080",
		authorizeParams("demo-spa", "http://localhost:5173/callback", "openid profile"),
		[]string{`name="password"`})
}
