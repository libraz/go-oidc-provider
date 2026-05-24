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
