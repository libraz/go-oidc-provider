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
//	(cd examples/52-prometheus-metrics && GOWORK=off go run -tags example .)
//
// Then read the curated counters:
//
//	# Drive at least one /token round-trip first so the vec metrics
//	# emit a sample (Prometheus vec collectors do not surface labels
//	# until they have been observed at least once).
//	curl -s http://127.0.0.1:8080/metrics | grep oidc_
//
// Curated counters surfaced by the library (canonical names; labels
// vary per metric — see internal/metrics/collector.go for shape):
//
//   - oidc_token_issued_total                       counter
//   - oidc_tokens_refreshed_total                   counter
//   - oidc_login_attempts_total                     counter
//   - oidc_refresh_replay_detected_total            counter
//   - oidc_code_replay_detected_total               counter
//   - oidc_client_authn_failures_total              counter
//   - oidc_dcr_events_total                         counter
//   - oidc_device_authorization_events_total        counter
//   - oidc_device_code_events_total                 counter
//   - oidc_ciba_events_total                        counter
//   - oidc_token_exchange_events_total              counter
//   - oidc_custom_grant_events_total                counter
//   - oidc_back_channel_logout_total                counter
//   - oidc_logout_failures_total                    counter
//   - oidc_introspection_errors_total               counter
//   - oidc_token_revoke_failures_total              counter
//   - oidc_dpop_loose_method_case_admitted_total    counter
//   - oidc_key_retired_kid_presented_total          counter
//
// The set is intentionally narrow — these are the events whose
// counters are not derivable from HTTP request logs and whose
// rate / total carries operational signal (refresh-token theft, brute
// force, code re-use, DCR/device-flow abuse). Embedders that want
// HTTP-level metrics (oidc_http_requests_total etc.) wrap the OP
// handler with promhttp.InstrumentHandlerCounter or otelhttp's
// middleware; the library deliberately does not do that itself.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - User seed: the demo username / password are hard-coded, and one [op.PrimaryPassword] step stands in for the whole login flow; production embedders enrol users through their own management plane and compose their own factors.
//   - /metrics surface: mounted on the same listener as the OP for brevity; production deployments expose /metrics on a management interface (separate listener, internal-only ingress).
package main

import (
	"context"
	"log"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/opkit"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

const (
	opAddr = ":8080"
	issuer = "http://127.0.0.1" + opAddr

	demoUsername = "demo"
	demoPassword = "demo-password"
	demoSubject  = "demo-user"
)

func main() {
	keys := devkeys.MustEphemeral("metrics-1")

	// The registry is the embedder's. The library only Registers;
	// the embedder mounts /metrics off the same registry so the
	// curated counters appear alongside the embedder's own metrics
	// (e.g. http_request_duration_seconds installed below).
	registry := prometheus.NewRegistry()

	memStore := inmem.New()
	if err := seedUser(memStore); err != nil {
		log.Fatalf("seed demo user: %v", err)
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(memStore),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		// oidc_login_attempts_total and oidc_token_issued_total only
		// move when somebody actually signs in, so the OP needs a
		// login flow for half the curated set to leave zero.
		op.WithLoginFlow(opkit.DefaultLoginFlow(memStore.UserPasswords())),
		// Admit "localhost" as a redirect_uri host alongside 127.0.0.1.
		op.WithAllowLocalhostLoopback(),
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

	log.Printf("prometheus-metrics example listening on %s (issuer %s; /metrics on the same listener)", opAddr, issuer)
	log.Printf("after at least one /token round-trip, curl -s %s/metrics | grep oidc_", issuer)
	log.Printf("demo user: username=%q password=%q", demoUsername, demoPassword)
	if err := serve.Listen(opAddr, mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// seedUser materialises the demo subject whose logins and token
// issuance move the curated counters. In a real deployment the user
// record comes from the embedder's identity backend.
func seedUser(st *inmem.Store) error {
	hash, err := op.HashPassword(demoPassword)
	if err != nil {
		return err
	}
	st.PutUserWithPassword(context.Background(), &store.User{
		Subject: demoSubject,
		Claims: map[string]any{
			"name":  "Demo User",
			"email": "demo@example.com",
		},
	}, demoUsername, hash)
	return nil
}
