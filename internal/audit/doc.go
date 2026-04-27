// Package audit emits structured audit events as slog records.
//
// The package is the single sink every internal handler routes audit
// events through. The handler-side surface is small on purpose: a
// fixed [Event] shape, an [Emitter] interface with one method, and
// two constructors ([Slog] for production, [Discard] for tests and
// the default no-op).
//
// The wire posture follows design 002 §N.3:
//
//   - Every record has slog attribute "audit"="true" so log shippers
//     can route audit lines to a separate retention bucket without
//     parsing the event name.
//   - The event name lands in attribute "event"; the level is
//     reflected as the record's slog level.
//   - The remaining fields (actor / target / client_id / session_id /
//     request_id / ip / user_agent) are emitted as top-level
//     attributes so dashboards can group on them directly.
//   - Free-form per-event fields ride in the [Event.Extras] group so
//     the canonical attribute set never collides with caller data.
//
// Redaction is the embedder's responsibility: when the slog handler
// is constructed via [op.WithAuditLogger], the op layer wraps it
// through [internal/redact] before it reaches this package, so
// secrets named after the canonical OAuth/OIDC keys (access_token,
// id_token, etc.) are masked even if a regression accidentally
// includes them in [Event.Extras].
package audit
