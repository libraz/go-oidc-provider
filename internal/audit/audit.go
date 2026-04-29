package audit

import (
	"context"
	"log/slog"

	"github.com/libraz/go-oidc-provider/internal/redact"
)

// Level is the audit-record severity. The values mirror the slog
// levels used at log time so a record at [LevelWarn] is emitted as
// a slog warn line.
type Level int

const (
	// LevelInfo records a routine but auditable event (e.g. token
	// issued, consent granted). Most records ride at this level.
	LevelInfo Level = iota

	// LevelWarn flags a security-relevant anomaly that did not
	// outright fail but warrants attention (e.g. expired IAT, refresh
	// replay detected, alg.legacy_used).
	LevelWarn

	// LevelError flags a condition that broke the audit invariant
	// itself (e.g. failed to persist a grant the caller already
	// observed). Rare; reserved for OP internal faults that affect
	// the audit guarantee.
	LevelError
)

// slogLevel maps the audit level onto its slog counterpart. The
// helper centralises the mapping so future levels (e.g. a critical
// bucket) flow through one place.
func (l Level) slogLevel() slog.Level {
	switch l {
	case LevelWarn:
		return slog.LevelWarn
	case LevelError:
		return slog.LevelError
	case LevelInfo:
		fallthrough
	default:
		return slog.LevelInfo
	}
}

// Event is the structural shape every audit record carries. New
// event-specific fields ride in [Event.Extras] so the canonical
// layer stays stable.
type Event struct {
	// Name is the canonical event identifier (e.g. "login.success",
	// "dcr.client.registered"). The catalogue lives on the public op/
	// surface as op.AuditEvent constants; handlers MUST select from
	// that closed list.
	Name string

	// Level is the severity classification. A zero value defaults to
	// [LevelInfo].
	Level Level

	// Message is a short human-readable description for operators.
	// It MUST NOT carry sensitive data — Extras is the place for
	// caller-controlled values, which the redactor sees.
	Message string

	// ActorID identifies the entity that triggered the event. For
	// user-initiated events this is the subject identifier; for
	// client-initiated flows it is the client_id. Empty when the
	// actor cannot yet be determined (e.g. unauthenticated 4xx).
	ActorID string

	// ClientID is the OAuth/OIDC client_id involved in the event,
	// when known. Empty for events that fire before a client is
	// identified (rare; almost all OAuth events resolve a client
	// first).
	ClientID string

	// SessionID is the OP session identifier the event is bound to,
	// when applicable. Empty for events that are not session-scoped
	// (e.g. token introspection).
	SessionID string

	// RequestID is the per-request correlation identifier (typically
	// the X-Request-ID header value). Useful for joining audit
	// records with operational logs.
	RequestID string

	// IP is the client IP observed at the OP edge after trusted-
	// proxy resolution. Empty when proxy resolution is disabled or
	// the request is internal.
	IP string

	// UserAgent is the User-Agent header value as observed at the
	// edge. Empty when the request did not supply one.
	UserAgent string

	// Tag is the IAT operator-supplied identifier for DCR events.
	// Empty for non-DCR events.
	Tag string

	// Extras carries event-specific fields the canonical layer does
	// not name. The map is emitted as a slog group named "extras";
	// keys inside follow the redactor's matching rules so a
	// regression that drops a token here is masked rather than
	// leaking.
	Extras map[string]any
}

// Emitter is the audit-sink contract. Handler code calls Emit
// unconditionally; the no-op emitter from [Discard] makes a nil
// guard unnecessary.
type Emitter interface {
	Emit(ctx context.Context, ev Event)
}

// Discard returns an [Emitter] that drops every record. It is the
// default when the embedder did not call op.WithAuditLogger, and the
// right choice in unit tests that do not assert on audit output.
//
//nolint:ireturn // Emitter is the package contract; the discard impl is private so callers must obtain it through this constructor.
func Discard() Emitter { return discardEmitter{} }

type discardEmitter struct{}

// Emit implements [Emitter] as a no-op.
func (discardEmitter) Emit(_ context.Context, _ Event) {}

// Slog returns an [Emitter] that emits each event as a structured
// slog record on logger. A nil logger collapses to [Discard] so the
// constructor cannot be the cause of a downstream nil-deref.
//
// Records are stamped with attribute "audit"="true" so log shippers
// can route audit lines to a dedicated retention bucket without
// parsing the event name. The remaining canonical fields ride as
// top-level attributes; [Event.Extras] is grouped under "extras".
//
//nolint:ireturn // Emitter is the package contract; the slog impl is private so callers must obtain it through this constructor.
func Slog(logger *slog.Logger) Emitter {
	if logger == nil {
		return Discard()
	}
	return &slogEmitter{logger: logger}
}

// slogEmitter is the production [Emitter]. The struct is intentionally
// minimal — the heavy lifting is in attrsFor — so the wire layout is
// easy to inspect when adding a new canonical field.
type slogEmitter struct {
	logger *slog.Logger
}

// Emit implements [Emitter] by routing the event to the underlying
// slog logger at the matching level. The record is constructed with
// [slog.Attr] rather than the variadic any form so the audit attribute
// is always the first key — log shippers that pre-route by leading
// attribute see "audit" up front.
func (e *slogEmitter) Emit(ctx context.Context, ev Event) {
	e.logger.LogAttrs(ctx, ev.Level.slogLevel(), ev.Message, attrsFor(ev)...)
}

// attrsFor flattens an [Event] into the slog attribute slice. Empty
// canonical fields are dropped so a record only carries the values
// the caller actually populated; this keeps audit lines compact and
// avoids the noise of `request_id=""` on every record.
func attrsFor(ev Event) []slog.Attr {
	attrs := make([]slog.Attr, 0, 10)
	attrs = append(attrs, slog.String("audit", "true"))
	attrs = append(attrs, slog.String("event", ev.Name))
	attrs = appendIfSet(attrs, "actor_id", ev.ActorID)
	attrs = appendIfSet(attrs, "client_id", ev.ClientID)
	attrs = appendIfSet(attrs, "session_id", ev.SessionID)
	attrs = appendIfSet(attrs, "request_id", ev.RequestID)
	attrs = appendIfSet(attrs, "ip", ev.IP)
	attrs = appendIfSet(attrs, "user_agent", ev.UserAgent)
	attrs = appendIfSet(attrs, "tag", ev.Tag)
	if len(ev.Extras) > 0 {
		extras := make([]slog.Attr, 0, len(ev.Extras))
		for k, v := range ev.Extras {
			extras = append(extras, extraAttr(k, v))
		}
		attrs = append(attrs, slog.Attr{Key: "extras", Value: slog.GroupValue(extras...)})
	}
	return attrs
}

// extraAttr converts a single Extras key/value pair into a slog
// attribute, masking the value with the redactor sentinel when the key
// (after canonicalisation) names a sensitive attribute. The
// belt-and-braces masking happens regardless of whether the embedder
// wraps their slog handler with [redact.WrapHandler]: an Extras map
// that carries a fresh refresh_token still ships as "[REDACTED]" to
// the underlying handler.
func extraAttr(k string, v any) slog.Attr {
	if redact.IsSensitive(k) {
		return slog.String(k, redact.Sentinel)
	}
	return slog.Any(k, v)
}

// appendIfSet appends a string attribute only when value is non-empty.
// The helper keeps attrsFor readable and the wire layout free of
// empty-string attributes.
func appendIfSet(attrs []slog.Attr, key, value string) []slog.Attr {
	if value == "" {
		return attrs
	}
	return append(attrs, slog.String(key, value))
}
