package metrics

import (
	"context"

	"github.com/libraz/go-oidc-provider/internal/audit"
)

// Bridge is an [audit.Emitter] that mirrors a curated subset of audit
// events onto the [Collector] counters and forwards every event
// verbatim to a downstream emitter. The forwarding step is
// unconditional so the slog audit stream is not lost when metrics
// are enabled.
//
// A nil downstream collapses onto [audit.Discard] so embedders that
// only want metrics can pass the [Bridge] in without first wrapping
// a discard sink.
type Bridge struct {
	c    *Collector
	next audit.Emitter
}

// NewBridge wires next behind c. A nil next is replaced with
// [audit.Discard] so [Bridge.Emit] can forward unconditionally without
// a per-call nil guard.
func NewBridge(c *Collector, next audit.Emitter) *Bridge {
	if next == nil {
		next = audit.Discard()
	}
	return &Bridge{c: c, next: next}
}

// Emit increments the counter matching ev.Name (when one exists) and
// forwards the event downstream. Events outside the curated subset
// are forwarded verbatim without touching any counter.
func (b *Bridge) Emit(ctx context.Context, ev audit.Event) {
	if b.c != nil {
		b.update(ev)
	}
	b.next.Emit(ctx, ev)
}

// update is the dispatch table. Splitting it out keeps the public
// Emit body small enough that the cyclop budget is unaffected by
// future events landing here.
func (b *Bridge) update(ev audit.Event) {
	switch ev.Name {
	case "token.issued":
		grant := stringExtra(ev.Extras, "grant_type")
		b.c.tokenIssued.WithLabelValues(grant, b.c.clientIDLabel(ev.ClientID)).Inc()
	case "login.success":
		b.c.loginAttempts.WithLabelValues("success", stringExtra(ev.Extras, "authenticator")).Inc()
	case "login.failed":
		b.c.loginAttempts.WithLabelValues("failed", stringExtra(ev.Extras, "authenticator")).Inc()
	case "refresh.replay_detected":
		b.c.refreshReplay.Inc()
	case "code.replay_detected":
		b.c.codeReplay.Inc()
	}
}

// stringExtra returns the string value at key, or "" when the entry
// is missing or stored under a non-string type. The defensive type
// assertion keeps a regression that swaps the value type from
// crashing the metric path.
func stringExtra(extras map[string]any, key string) string {
	if extras == nil {
		return ""
	}
	v, ok := extras[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}
