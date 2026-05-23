package metrics

import (
	"context"
	"log/slog"
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
	b.next.Emit(ctx, ev)
	if b.c != nil {
		b.safeUpdate(ev)
	}
}

func (b *Bridge) safeUpdate(ev audit.Event) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		// A panic in collector update would otherwise vanish silently and
		// hide a real metric-side bug. Log via slog.Default so the trace
		// reaches whichever sink the embedder installed, without taking
		// the audit forwarding path down with it.
		slog.Default().Warn("metrics bridge: collector update panicked",
			slog.String("event", ev.Name),
			slog.Any("panic", r),
		)
	}()
	b.update(ev)
}

// update is the dispatch entrypoint. The body is a small router that
// delegates to category-specific helpers; this keeps each helper short
// and within the cyclop budget as new event names land.
func (b *Bridge) update(ev audit.Event) {
	switch {
	case b.updateFlowEvents(ev):
	case b.updateOperationalEvents(ev):
	case strings.HasPrefix(ev.Name, "dcr."):
		b.c.dcrEvents.WithLabelValues(allowlistedEventLabel(ev.Name, "dcr.", dcrEventLabels)).Inc()
	case strings.HasPrefix(ev.Name, "device_authorization."):
		b.c.deviceAuthorizationEvents.WithLabelValues(allowlistedEventLabel(ev.Name, "device_authorization.", deviceAuthorizationEventLabels)).Inc()
	case strings.HasPrefix(ev.Name, "device_code."):
		b.c.deviceCodeEvents.WithLabelValues(allowlistedEventLabel(ev.Name, "device_code.", deviceCodeEventLabels)).Inc()
	case strings.HasPrefix(ev.Name, "ciba."):
		b.c.cibaEvents.WithLabelValues(allowlistedEventLabel(ev.Name, "ciba.", cibaEventLabels)).Inc()
	case strings.HasPrefix(ev.Name, "token_exchange."):
		b.c.tokenExchangeEvents.WithLabelValues(allowlistedEventLabel(ev.Name, "token_exchange.", tokenExchangeEventLabels)).Inc()
	case strings.HasPrefix(ev.Name, "logout.back_channel."):
		b.c.backChannelLogout.WithLabelValues(allowlistedEventLabel(ev.Name, "logout.back_channel.", backChannelLogoutLabels)).Inc()
	}
}

const unknownEventLabel = "unknown"

var (
	dcrEventLabels = map[string]struct{}{
		"client.registered":                         {},
		"client.metadata_read":                      {},
		"client.metadata_updated":                   {},
		"client.deleted":                            {},
		"iat.consumed":                              {},
		"iat.expired":                               {},
		"iat.invalid":                               {},
		"rat.invalid":                               {},
		"metadata.validation_failed":                {},
		"open_registration_used":                    {},
		"cascade.refresh_revoke_failed":             {},
		"cascade.grant_revoke_failed":               {},
		"cascade.access_token_revoke_failed":        {},
		"cascade.opaque_access_token_revoke_failed": {},
	}
	deviceAuthorizationEventLabels = map[string]struct{}{
		"issued":           {},
		"rejected":         {},
		"unbound_rejected": {},
	}
	deviceCodeEventLabels = map[string]struct{}{
		"token.issued":                       {},
		"token.rejected":                     {},
		"token.slow_down":                    {},
		"verification.approved":              {},
		"verification.denied":                {},
		"verification.user_code_brute_force": {},
		"revoked":                            {},
	}
	cibaEventLabels = map[string]struct{}{
		"authorization.issued":           {},
		"authorization.rejected":         {},
		"authorization.unbound_rejected": {},
		"auth_device.approved":           {},
		"auth_device.denied":             {},
		"poll_abuse.lockout":             {},
		"poll_observation.failed":        {},
		"token.issued":                   {},
		"token.rejected":                 {},
		"token.slow_down":                {},
	}
	tokenExchangeEventLabels = map[string]struct{}{
		"requested":                    {},
		"granted":                      {},
		"policy_denied":                {},
		"policy_error":                 {},
		"scope_inflation_blocked":      {},
		"audience_blocked":             {},
		"ttl_capped":                   {},
		"act_chain_too_deep":           {},
		"empty_scope_rejected":         {},
		"actor_equals_subject":         {},
		"subject_token_external":       {},
		"actor_token_external":         {},
		"subject_token_invalid":        {},
		"refresh_issued":               {},
		"self_exchange":                {},
		"subject_token_registry_error": {},
	}
	backChannelLogoutLabels = map[string]struct{}{
		"delivered": {},
		"failed":    {},
	}
)

func allowlistedEventLabel(name, prefix string, allowed map[string]struct{}) string {
	label := strings.TrimPrefix(name, prefix)
	if _, ok := allowed[label]; ok {
		return label
	}
	return unknownEventLabel
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
