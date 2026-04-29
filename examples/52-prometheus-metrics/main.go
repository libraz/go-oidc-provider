//go:build example

// Example 52 demonstrates the WithPrometheus seam. The OP registers
// a curated counter set on the embedder-supplied registry and updates
// the counters from its internal audit-event emission chain. The
// embedder owns the HTTP request lifecycle (request duration
// histograms, status code labels) and the /metrics surface — the
// library never mounts /metrics or wraps the request handler.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/52-prometheus-metrics
//
// Then read the curated counters:
//
//	# Drive at least one /token round-trip first so the vec metrics
//	# emit a sample (Prometheus vec collectors do not surface labels
//	# until they have been observed at least once).
//	curl -s http://localhost:9090/metrics | grep oidc_
//
// Curated counters surfaced by the library (canonical names; labels
// vary per metric — see internal/metrics/collector.go for shape):
//
//   - oidc_token_issued_total               counter
//   - oidc_login_attempts_total             counter
//   - oidc_refresh_replay_detected_total    counter
//   - oidc_code_replay_detected_total       counter
//
// The set is intentionally narrow — these are the events whose
// counters are not derivable from HTTP request logs and whose
// rate / total carries operational signal (refresh-token theft, brute
// force, code re-use). Embedders that want HTTP-level metrics
// (oidc_http_requests_total etc.) wrap the OP handler with
// promhttp.InstrumentHandlerCounter or otelhttp's middleware; the
// library deliberately does not do that itself per
// docs/plans/002-product-design.md §F.4.
//
// PRODUCTION CAVEATS: this example mounts /metrics on the same listener
// as the OP for brevity; production deployments expose /metrics on a
// management interface (separate listener, internal-only ingress)
// and front the OP behind TLS-terminating ingress.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func main() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate signing key: %v", err)
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		log.Fatalf("generate cookie key: %v", err)
	}

	// The registry is the embedder's. The library only Registers;
	// the embedder mounts /metrics off the same registry so the
	// curated counters appear alongside the embedder's own metrics
	// (e.g. http_request_duration_seconds installed below).
	registry := prometheus.NewRegistry()

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(op.Keyset{{KeyID: "metrics-1", Signer: priv}}),
		op.WithCookieKey(cookieKey),
		op.WithPrometheus(registry),
		op.WithStaticClients(
			op.PublicClient{
				ID:           "demo-spa",
				RedirectURIs: []string{"http://localhost:5173/callback"},
				Scopes:       []string{"openid", "profile"},
			},
		),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	// /metrics belongs to the embedder. The library deliberately
	// does not mount it. promhttp.HandlerFor scopes the surfaced
	// metrics to the registry the OP shares — no global /metrics.
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	mux.Handle("/", provider)

	log.Println("prometheus-metrics example listening on :8080 (OP) and :8080/metrics")
	log.Println("after at least one /token round-trip, curl -s :8080/metrics | grep oidc_")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
