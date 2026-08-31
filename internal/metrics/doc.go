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
//     site needing to know. Exact event-to-counter mappings come from
//     internal/auditevent, the same typed registry projected by
//     op.AuditEventCatalog; unknown extension names remain audit-only.
//   - Cardinality safety: client_id is the only label whose value can
//     arrive from the wire, and it is the only one gated at the
//     bridge — it is projected through the closed static-client set,
//     so a client without a static-seed entry collapses onto the empty
//     client_id label. Every other label is bounded at its source
//     instead: result, kind and event are read off the catalog row,
//     while factor, auth_method and reason are forwarded verbatim from
//     the emitting path, which selects them from a fixed vocabulary of
//     its own. An embedder therefore owns the cardinality of the
//     labels their code supplies — a custom [op.Authenticator] whose
//     Type() varies per user or per request widens
//     oidc_login_attempts_total directly, and Type() MUST return one
//     of a small set fixed at configuration time. PII labels (subject,
//     IP, user-agent) are never emitted.
//   - Registry ownership: the [prometheus.Registry] is the embedder's.
//     Every metric carries the OP issuer as a constant label, so several
//     Providers in one process can share a single registry without a
//     name collision and without the metric names shifting under
//     existing dashboards. Unregister is called only to roll back a
//     failed [New], never on a live collector. Re-registering the same
//     issuer surfaces the standard [prometheus.AlreadyRegisteredError]
//     so the embedder can decide how to recover.
//
// The package depends on [github.com/prometheus/client_golang]; the
// dependency is gated to this directory so the rest of the codebase
// stays Prometheus-agnostic.
package metrics
