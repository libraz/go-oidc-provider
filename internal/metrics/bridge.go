package metrics

import (
	"context"
	"strings"

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

// update is the dispatch entrypoint. The body is a small router that
// delegates to category-specific helpers; this keeps each helper short
// and within the cyclop budget as new event names land.
func (b *Bridge) update(ev audit.Event) {
	switch {
	case b.updateFlowEvents(ev):
	case b.updateOperationalEvents(ev):
	case strings.HasPrefix(ev.Name, "dcr."):
		b.c.dcrEvents.WithLabelValues(strings.TrimPrefix(ev.Name, "dcr.")).Inc()
	case strings.HasPrefix(ev.Name, "device_authorization."):
		b.c.deviceAuthorizationEvents.WithLabelValues(strings.TrimPrefix(ev.Name, "device_authorization.")).Inc()
	case strings.HasPrefix(ev.Name, "device_code."):
		b.c.deviceCodeEvents.WithLabelValues(strings.TrimPrefix(ev.Name, "device_code.")).Inc()
	case strings.HasPrefix(ev.Name, "ciba."):
		b.c.cibaEvents.WithLabelValues(strings.TrimPrefix(ev.Name, "ciba.")).Inc()
	case strings.HasPrefix(ev.Name, "token_exchange."):
		b.c.tokenExchangeEvents.WithLabelValues(strings.TrimPrefix(ev.Name, "token_exchange.")).Inc()
	case strings.HasPrefix(ev.Name, "logout.back_channel."):
		b.c.backChannelLogout.WithLabelValues(strings.TrimPrefix(ev.Name, "logout.back_channel.")).Inc()
	}
}

// updateFlowEvents handles token / login flow events. The split from
// [Bridge.updateOperationalEvents] keeps each helper inside the cyclop
// budget as new event names land.
func (b *Bridge) updateFlowEvents(ev audit.Event) bool {
	switch ev.Name {
	case "token.issued":
		b.c.tokenIssued.WithLabelValues(stringExtra(ev.Extras, "grant_type"), b.c.clientIDLabel(ev.ClientID)).Inc()
	case "token.refreshed":
		b.c.tokensRefreshed.WithLabelValues(b.c.clientIDLabel(ev.ClientID)).Inc()
	case "login.success":
		b.c.loginAttempts.WithLabelValues("success", stringExtra(ev.Extras, "authenticator")).Inc()
	case "login.failed":
		b.c.loginAttempts.WithLabelValues("failed", stringExtra(ev.Extras, "authenticator")).Inc()
	case "refresh.replay_detected":
		b.c.refreshReplay.Inc()
	case "code.replay_detected":
		b.c.codeReplay.Inc()
	case "client_authn.failure":
		b.c.clientAuthnFailures.WithLabelValues(
			stringExtra(ev.Extras, "method"),
			stringExtra(ev.Extras, "reason"),
		).Inc()
	default:
		return false
	}
	return true
}

// updateOperationalEvents handles silent-failure / single-counter
// signals that do not share a category prefix.
func (b *Bridge) updateOperationalEvents(ev audit.Event) bool {
	switch ev.Name {
	case "bcl.no_sessions_for_subject":
		b.c.backChannelLogout.WithLabelValues("no_sessions_for_subject").Inc()
	case "introspection.error":
		b.c.introspectionErrors.Inc()
	case "token.revoke_failed":
		b.c.tokenRevokeFailures.WithLabelValues("token").Inc()
	case "refresh.chain_revoke_failed":
		b.c.tokenRevokeFailures.WithLabelValues("refresh_chain").Inc()
	case "refresh.grant_revoke_failed":
		b.c.tokenRevokeFailures.WithLabelValues("refresh_grant").Inc()
	case "dpop.loose_method_case_admitted":
		b.c.dpopLooseMethodCase.Inc()
	case "key.retired_kid_presented":
		b.c.keyRetiredKidPresented.Inc()
	default:
		return false
	}
	return true
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
