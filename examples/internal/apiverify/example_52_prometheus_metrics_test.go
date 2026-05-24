//go:build apiverify

package apiverify

import "testing"

func TestExample52PrometheusMetrics(t *testing.T) {
	runDiscovery(t, "../../52-prometheus-metrics", "http://127.0.0.1:8080")
}
