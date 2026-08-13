package metrics

import (
	"context"
	"log/slog"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/op/store"
)

// unknownGrantType is the grant_type label for a first refresh-token
// issuance whose origin is absent or outside the closed set below. It is
// deliberately not one of the real grant labels: a record that cannot
// prove which grant minted it must not be counted as one that can.
const unknownGrantType = "unknown"

// refreshOriginLabels projects the persisted refresh-chain origin onto
// the grant_type label. The map is closed, so the label cardinality is
// the number of rows here plus unknownGrantType, whatever an event
// carries.
//
//nolint:gochecknoglobals // immutable closed projection.
var refreshOriginLabels = map[store.RefreshTokenOrigin]string{
	store.RefreshOriginAuthCode:    "authorization_code",
	store.RefreshOriginDeviceCode:  "device_code",
	store.RefreshOriginCIBA:        "ciba",
	store.RefreshOriginCustomGrant: "custom_grant",
}

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

// update resolves the exact event in the shared registry before selecting a
// collector. Unknown names are audit-only: prefix resemblance is never enough
// to create a metric label.
func (b *Bridge) update(ev audit.Event) {
	definition, ok := auditevent.Lookup(ev.Name)
	if !ok {
		return
	}
	if b.updateFlowMetric(definition, ev) {
		return
	}
	if b.updateCategoryMetric(definition) {
		return
	}
	b.updateOperationalMetric(definition)
}

func (b *Bridge) updateFlowMetric(definition auditevent.Definition, ev audit.Event) bool {
	switch definition.Metric {
	case auditevent.MetricTokenIssued:
		// This event is emitted only when a grant actually persists a first
		// refresh token; every such grant stamps the origin it recorded on
		// the chain, so the label names the grant that minted it (refresh
		// rotation has its own event and metric).
		b.c.tokenIssued.WithLabelValues(refreshGrantTypeLabel(ev.Extras), b.c.clientIDLabel(ev.ClientID)).Inc()
	case auditevent.MetricTokensRefreshed:
		b.c.tokensRefreshed.WithLabelValues(b.c.clientIDLabel(ev.ClientID)).Inc()
	case auditevent.MetricLoginAttempts:
		b.c.loginAttempts.WithLabelValues(stringExtra(ev.Extras, "factor"), definition.Label).Inc()
	case auditevent.MetricRefreshReplay:
		b.c.refreshReplay.Inc()
	case auditevent.MetricCodeReplay:
		b.c.codeReplay.Inc()
	case auditevent.MetricClientAuthnFailures:
		b.c.clientAuthnFailures.WithLabelValues(
			stringExtra(ev.Extras, "method"),
			stringExtra(ev.Extras, "reason"),
		).Inc()
	default:
		return false
	}
	return true
}

func (b *Bridge) updateCategoryMetric(definition auditevent.Definition) bool {
	switch definition.Metric {
	case auditevent.MetricDCR:
		b.c.dcrEvents.WithLabelValues(definition.Label).Inc()
	case auditevent.MetricDeviceAuthorization:
		b.c.deviceAuthorizationEvents.WithLabelValues(definition.Label).Inc()
	case auditevent.MetricDeviceCode:
		b.c.deviceCodeEvents.WithLabelValues(definition.Label).Inc()
	case auditevent.MetricCIBA:
		b.c.cibaEvents.WithLabelValues(definition.Label).Inc()
	case auditevent.MetricTokenExchange:
		b.c.tokenExchangeEvents.WithLabelValues(definition.Label).Inc()
	case auditevent.MetricCustomGrant:
		b.c.customGrantEvents.WithLabelValues(definition.Label).Inc()
	case auditevent.MetricBackChannelLogout:
		b.c.backChannelLogout.WithLabelValues(definition.Label).Inc()
	default:
		return false
	}
	return true
}

func (b *Bridge) updateOperationalMetric(definition auditevent.Definition) {
	switch definition.Metric {
	case auditevent.MetricLogoutFailures:
		b.c.logoutFailures.WithLabelValues(definition.Label).Inc()
	case auditevent.MetricIntrospectionErrors:
		b.c.introspectionErrors.Inc()
	case auditevent.MetricTokenRevokeFailures:
		b.c.tokenRevokeFailures.WithLabelValues(definition.Label).Inc()
	case auditevent.MetricDPoPLooseMethodCase:
		b.c.dpopLooseMethodCase.Inc()
	case auditevent.MetricKeyRetiredKidPresented:
		b.c.keyRetiredKidPresented.Inc()
	default:
		return
	}
}

// refreshGrantTypeLabel derives the grant_type label from the origin the
// issuance path stamped on the event. The value is read as a
// [store.RefreshTokenOrigin] and then resolved through the closed
// projection, so neither a string planted under the same key — the only
// shape request-derived data takes — nor an origin the projection does
// not know can present itself as a grant: both land on
// unknownGrantType.
func refreshGrantTypeLabel(extras map[string]any) string {
	origin, ok := extras[auditevent.ExtraRefreshOrigin].(store.RefreshTokenOrigin)
	if !ok {
		return unknownGrantType
	}
	label, ok := refreshOriginLabels[origin]
	if !ok {
		return unknownGrantType
	}
	return label
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
