package op

import "time"

// BackchannelAllowsPrivateNetwork reports whether
// [WithAllowPrivateNetworkBackchannel] (or the deprecated
// [WithBackchannelAllowPrivateNetwork] with true) was applied to this config. The wiring layer (op_builders.go) consults the
// accessor when constructing the back-channel deliverer so the
// per-config gate flows through to the SSRF check.
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

// WithAllowPrivateNetworkBackchannel suppresses the SSRF deny-list
// the back-channel logout deliverer applies to RP-controlled
// backchannel_logout_uri values. Without it the deliverer rejects
// loopback / link-local / RFC 1918 / IPv6 ULA destinations, so a
// hostile RP cannot register backchannel_logout_uri =
// "http://127.0.0.1/..." or "http://169.254.169.254/..." and have the
// OP POST a signed logout_token at an internal service.
//
// Embedders that front their RPs with private DNS — typical in
// service-mesh deployments where the RP and the OP share a pod
// network — opt in with this option. It flips the gate at the
// deliverer level only; the other fetchers keep their own
// WithAllowPrivateNetwork* flags ([WithAllowPrivateNetworkJWKS],
// [WithAllowPrivateNetworkJAR], ...) so private-network access granted
// to one never widens another.
//
// Stable since v1.5.
func WithAllowPrivateNetworkBackchannel() Option {
	return optionFunc(func(c *config) error {
		if err := c.claimSlot(slotBackchannelAllowPrivateNetwork, "WithAllowPrivateNetworkBackchannel"); err != nil {
			return err
		}
		c.backchannelAllowPrivateNetwork = true
		return nil
	})
}

// WithBackchannelAllowPrivateNetwork sets the gate
// [WithAllowPrivateNetworkBackchannel] opens; false leaves it closed.
//
// Deprecated: use [WithAllowPrivateNetworkBackchannel], named like the
// other WithAllowPrivateNetwork* options.
//
// Stable since v1.0.
func WithBackchannelAllowPrivateNetwork(allow bool) Option {
	return optionFunc(func(c *config) error {
		if err := c.claimSlot(slotBackchannelAllowPrivateNetwork, "WithBackchannelAllowPrivateNetwork"); err != nil {
			return err
		}
		c.backchannelAllowPrivateNetwork = allow
		return nil
	})
}

// slotBackchannelAllowPrivateNetwork is the single-valued setting both
// back-channel private-network options claim, so supplying both is
// refused as a conflict.
const slotBackchannelAllowPrivateNetwork = "backchannelAllowPrivateNetwork"

// WithBackchannelFanOutBudget caps the total wall-clock time one
// back-channel logout fan-out may occupy. The /end_session handler
// terminates the OP-side session, starts the fan-out on a detached
// context, and answers the browser immediately, so this budget — not
// the end-user's request — is what bounds the lifetime of the
// outbound work.
//
// The budget is a whole-event cap and is therefore distinct from
// [WithBackchannelLogoutTimeout], which bounds a single RP's POST.
// The two compose: an audience larger than the delivery worker pool
// is notified in waves, so the per-RP timeout alone would let a fully
// unresponsive audience occupy many multiples of itself. Deliveries
// abandoned when the budget elapses fail with the context error and
// raise [AuditLogoutBackChannelFailed], so an under-sized budget is
// visible in the audit stream rather than silent.
//
// Not calling the option selects the library default of 30 seconds,
// which suits an audience of a few dozen responsive RPs. Raise it for
// deployments where one subject holds grants with many RPs; lower it
// where the deployment would rather shed a slow logout than hold
// outbound connections open. A non-positive duration is rejected at
// the option site — "no budget" is not an expressible posture,
// because an unbounded fan-out would outlive any shutdown deadline
// [Provider.Shutdown] is given.
//
// Stable since v1.1.
func WithBackchannelFanOutBudget(d time.Duration) Option {
	return optionFunc(func(c *config) error {
		if err := c.claimOnce("WithBackchannelFanOutBudget"); err != nil {
			return err
		}
		if d <= 0 {
			return newConfigurationError("WithBackchannelFanOutBudget requires a positive duration", nil)
		}
		c.backchannelFanOutBudget = d
		return nil
	})
}
