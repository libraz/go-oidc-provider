package op

import (
	"net/http"
	"time"
)

// BackchannelAllowsPrivateNetwork reports whether
// [WithAllowPrivateNetwork] listed [OutboundBackchannel] on this config.
// The wiring layer (op_builders.go) consults the accessor when
// constructing the back-channel deliverer so the per-config gate flows
// through to the SSRF check.
//
// The accessor is the only path through which the SSRF gate's
// inversion is exposed to the wiring layer; tests that need to
// observe the flag drive the option, not this method.
func (c *config) BackchannelAllowsPrivateNetwork() bool {
	if c == nil {
		return false
	}
	return c.backchannelAllowPrivateNetwork
}

// BackchannelLogout tunes the back-channel logout fan-out ([WithBackchannelLogout]).
// A zero field selects the library default.
//
// Stable since v1.5.
type BackchannelLogout struct {
	// Transport is the [http.RoundTripper] the coordinator uses when
	// POSTing Logout Tokens to relying parties. Most embedders do not need
	// it — the default is correct for the spec posture. Supply one for
	// shared instrumentation or an internal CA.
	//
	// The coordinator always applies [BackchannelLogout.Timeout], rejects
	// redirects, and checks every request URL against the SSRF deny-list.
	// A nil Transport or an [*http.Transport] also gets the dial-time
	// check: the transport is cloned and its DialContext, DialTLSContext
	// and DialTLS are replaced by the OP's gated dialer, so the proxy, TLS
	// and pool settings carry over but a custom dial function does not.
	// Through a proxy the dial-time check covers the proxy's address; the
	// target URL is checked once before the hand-off and the proxy resolves
	// it independently. Any other [http.RoundTripper] (an otelhttp wrap,
	// for instance) is gated on the request URL only, which does not stop a
	// DNS-rebinding peer that resolves public when the URL is checked and
	// private when it is dialled.
	Transport http.RoundTripper

	// Timeout caps the time the OP spends waiting for a single relying
	// party to acknowledge a Logout Token POST. The budget applies per RP;
	// the coordinator dispatches in parallel, so a slow RP does not delay
	// deliveries to its peers. Zero selects the default of 5 seconds. Keep
	// the value low — back-channel logout is best-effort, and a long
	// timeout merely keeps the OP holding state on a likely-broken RP. A
	// negative value fails [New].
	Timeout time.Duration

	// FanOutBudget caps the total wall-clock time one back-channel logout
	// fan-out may occupy. The /end_session handler terminates the OP-side
	// session, starts the fan-out on a detached context, and answers the
	// browser immediately, so this budget — not the end-user's request — is
	// what bounds the lifetime of the outbound work.
	//
	// The budget is a whole-event cap and is therefore distinct from
	// Timeout, which bounds a single RP's POST. The two compose: an
	// audience larger than the delivery worker pool is notified in waves,
	// so the per-RP timeout alone would let a fully unresponsive audience
	// occupy many multiples of itself. Deliveries abandoned when the budget
	// elapses fail with the context error and raise
	// audit.LogoutBackChannelFailed, so an under-sized budget is visible
	// in the audit stream rather than silent.
	//
	// Zero selects the library default of 30 seconds, which suits an
	// audience of a few dozen responsive RPs. Raise it for deployments
	// where one subject holds grants with many RPs; lower it where the
	// deployment would rather shed a slow logout than hold outbound
	// connections open. "No budget" is not expressible — an unbounded
	// fan-out would outlive any shutdown deadline [Provider.Shutdown] is
	// given — so a negative value fails [New].
	FanOutBudget time.Duration
}

// WithBackchannelLogout tunes the OpenID Connect Back-Channel Logout 1.0
// delivery: the outbound transport, the per-RP timeout and the whole
// fan-out budget. Zero fields in b keep their defaults, and not calling the
// option keeps all of them.
//
// # Delivery integrity
//
// Back-channel logout fan-out walks the active grants the OP
// remembers for the terminating subject. The walk's coverage is
// bounded by the durability of the [op/store.SessionStore] and the
// [op/store.GrantStore] backing the OP: under volatile placement
// (Redis without persistence, Memcached, in-memory under maxmemory
// eviction) a session evicted between establishment and logout
// silently removes the rows the coordinator would walk, narrowing
// OIDC Back-Channel Logout 1.0 §2.7's best-effort floor to zero.
// Embedders who require at-least-once delivery for every initiated
// logout MUST route SessionStore to a durable backend; the
// `bcl.no_sessions_for_subject` audit event (audit.BCLNoSessionsForSubject)
// surfaces the gap when it actually fires. Declare the chosen
// posture through [WithSessionDurabilityPosture] so the audit
// signal carries the embedder's intent.
//
// At most one call is accepted; a second call fails [New].
//
// Stable since v1.5.
func WithBackchannelLogout(b BackchannelLogout) Option {
	return optionFunc(func(c *config) error {
		if err := c.claimOnce("WithBackchannelLogout"); err != nil {
			return err
		}
		if b.Timeout < 0 {
			return newConfigurationError("WithBackchannelLogout: Timeout must not be negative (zero selects the default)", nil)
		}
		if b.FanOutBudget < 0 {
			return newConfigurationError("WithBackchannelLogout: FanOutBudget must not be negative (zero selects the default)", nil)
		}
		c.backchannelLogoutTransport = b.Transport
		c.backchannelLogoutTimeout = b.Timeout
		c.backchannelFanOutBudget = b.FanOutBudget
		return nil
	})
}
