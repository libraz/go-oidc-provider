// Package metrics integrates a curated Prometheus counter set with the
// OP runtime. The package is wired exclusively through
// [op.WithPrometheus]; it has no public surface of its own.
//
// Scope is deliberately narrow: counters are sourced from the OP's
// audit-event emission chain. The HTTP request lifecycle (per-endpoint
// duration histograms, request totals by method, etc.) is the
// embedder's responsibility — the OP is a library that returns an
// [http.Handler], so request-level observability slots in upstream
// (e.g. promhttp middleware) without this package needing to wrap the
// router.
//
// The integration follows three structural rules:
//
//   - Audit-bridge pattern: counters are sourced from the same
//     [audit.Emitter] chain the OP already drives. The [Bridge] type
//     wraps a downstream emitter, increments the matching counter, and
//     forwards the event verbatim — so a single emission updates both
//     the slog audit stream and the metric counter without the call
//     site needing to know.
//   - Cardinality safety: every label value drawn from caller-
//     controlled input (client_id, authenticator name) is gated
//     through a closed allowlist before being emitted. Dynamic
//     clients without a static-seed entry collapse onto the empty
//     client_id label. PII labels (subject, IP, user-agent) are never
//     emitted.
//   - Registry ownership: the [prometheus.Registry] is the embedder's;
//     this package only calls Register, never Unregister. Re-registering
//     on the same registry surfaces the standard
//     [prometheus.AlreadyRegisteredError] from [Collector.New] so the
//     embedder can decide how to recover.
//
// The package depends on [github.com/prometheus/client_golang]; the
// dependency is gated to this directory so the rest of the codebase
// stays Prometheus-agnostic.
package metrics
