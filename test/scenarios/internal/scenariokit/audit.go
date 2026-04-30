package scenariokit

import (
	"context"
	"log/slog"
	"sync"
)

// AuditEvent is a captured snapshot of an audit-stamped slog record.
// Only the fields tests typically assert on are extracted; the full
// attribute slice is preserved on [AuditEvent.Attrs] for callers that
// need to inspect specifics (extras, request_id, ...).
type AuditEvent struct {
	// Name is the canonical event identifier ("grant.success",
	// "login.success", ...). Pulled from the "event" slog attribute.
	Name string

	// Message is the human-readable message slog stamped onto the
	// record at log time.
	Message string

	// Level is the slog level at which the event was emitted.
	Level slog.Level

	// Attrs is the verbatim attribute slice the slog handler saw.
	// Tests that need to inspect "extras", "client_id", "actor_id"
	// pull from here.
	Attrs []slog.Attr
}

// AuditCapture records every audit-stamped slog record emitted
// through [AuditCapture.Logger]. Records that lack the canonical
// audit="true" marker are dropped on the floor — the capture is
// scoped to OIDC audit traffic so a verbose root logger does not
// pollute the recorded list.
//
// AuditCapture is safe for concurrent use.
type AuditCapture struct {
	mu     sync.Mutex
	events []AuditEvent
	logger *slog.Logger
}

// NewAuditCapture returns a fresh capture wired to a [slog.Logger]
// callers pass through [op.WithAuditLogger]. The logger only routes
// audit-stamped records into [AuditCapture.Events]; non-audit log
// lines are discarded.
func NewAuditCapture() *AuditCapture {
	c := &AuditCapture{}
	c.logger = slog.New(&captureHandler{parent: c})
	return c
}

// Logger returns the [slog.Logger] callers thread into
// [op.WithAuditLogger]. Calling Logger before NewAuditCapture is a
// programming error; the type does not expose a zero-value path.
func (c *AuditCapture) Logger() *slog.Logger { return c.logger }

// Events returns a copy of the captured events. The returned slice
// is independent of the capture's internal state, so the caller can
// mutate / sort it freely.
func (c *AuditCapture) Events() []AuditEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]AuditEvent, len(c.events))
	copy(out, c.events)
	return out
}

// EventsByName returns every captured event whose Name matches.
// Useful when a test needs to count "grant.success" emissions
// without iterating manually.
func (c *AuditCapture) EventsByName(name string) []AuditEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []AuditEvent
	for _, ev := range c.events {
		if ev.Name == name {
			out = append(out, ev)
		}
	}
	return out
}

// captureHandler is the slog.Handler that feeds [AuditCapture].
// It implements the minimum surface slog needs (Enabled / Handle /
// WithAttrs / WithGroup) and filters on audit="true" so non-audit
// records do not enter the capture.
type captureHandler struct {
	parent *AuditCapture
	attrs  []slog.Attr
	group  string
}

// Enabled implements [slog.Handler]. It always returns true so the
// capture sees every level; tests filter at assertion time.
func (h *captureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

// Handle implements [slog.Handler]. It records the event when the
// "audit" marker is present.
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	attrs := append([]slog.Attr{}, h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})
	if !hasAuditMarker(attrs) {
		return nil
	}
	ev := AuditEvent{
		Message: r.Message,
		Level:   r.Level,
		Attrs:   attrs,
	}
	for _, a := range attrs {
		if a.Key == "event" {
			ev.Name = a.Value.String()
			break
		}
	}
	h.parent.mu.Lock()
	h.parent.events = append(h.parent.events, ev)
	h.parent.mu.Unlock()
	return nil
}

// WithAttrs implements [slog.Handler]. The returned handler shares
// the underlying capture so attribute scoping (typically not used by
// the audit emitter, but allowed by the contract) does not split the
// recorded stream.
func (h *captureHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := *h
	out.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &out
}

// WithGroup implements [slog.Handler]. Groups are flattened (the
// audit emitter uses one anyway, "extras"); recording the group name
// is enough for the rare callers that consult Attrs by key.
func (h *captureHandler) WithGroup(name string) slog.Handler {
	out := *h
	out.group = name
	return &out
}

// hasAuditMarker reports whether attrs include the canonical
// audit="true" marker the [audit.Slog] emitter stamps onto every
// record.
func hasAuditMarker(attrs []slog.Attr) bool {
	for _, a := range attrs {
		if a.Key == "audit" && a.Value.String() == "true" {
			return true
		}
	}
	return false
}
