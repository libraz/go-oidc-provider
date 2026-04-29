package op

import (
	"sync"
)

// protocolOptionState carries per-config protocol-layer settings the
// audit-driven security hardening introduces. The state is stored
// out-of-line (a private sync.Map keyed by the *config pointer) so
// that the new options can be added without growing the [config]
// struct's surface; the indirection lets this file expose the public
// [Option] entry points while the wiring layer (op.go) reads the
// resulting values back through accessor methods declared here.
//
// The map is intentionally write-once-per-config: each [optionFunc]
// runs exactly once during [newConfig], so storing a fresh
// [protocolOptionState] keyed by the config pointer is a write
// without lock contention. Reads happen on the request path through
// the wiring layer; the sync.Map's concurrent-read guarantee is
// sufficient because the entry is never updated after [newConfig]
// returns.
//
//nolint:gochecknoglobals // package-level registry intentionally scoped to the protocol-options surface; a struct field would force a touch on the existing [config] declaration.
var protocolOptionsState sync.Map

// protocolOptionState is the per-config payload [protocolOptionsState]
// carries. The field set is closed: every option declared in this
// file maps onto exactly one boolean / interface / value.
type protocolOptionState struct {
	// backchannelAllowPrivateNetwork mirrors
	// [op.WithBackchannelAllowPrivateNetwork]; when true the back-
	// channel logout deliverer's SSRF deny-list is suppressed. The
	// default false rejects loopback / link-local / RFC 1918 hosts
	// so an attacker-controlled backchannel_logout_uri cannot pivot
	// the OP onto an internal service.
	backchannelAllowPrivateNetwork bool
}

// loadProtocolState returns the [protocolOptionState] associated
// with c, or a zero value when no protocol option has run against
// the config. The accessor never allocates — the zero value is
// returned by value — so the read path stays cheap.
func loadProtocolState(c *config) protocolOptionState {
	if c == nil {
		return protocolOptionState{}
	}
	v, ok := protocolOptionsState.Load(c)
	if !ok {
		return protocolOptionState{}
	}
	st, ok := v.(*protocolOptionState)
	if !ok || st == nil {
		return protocolOptionState{}
	}
	return *st
}

// mutateProtocolState invokes mutate on the [protocolOptionState]
// associated with c, creating one when absent. The function returns
// nothing because every protocol option is a void mutation; errors
// are surfaced through the [Option]'s own return value.
func mutateProtocolState(c *config, mutate func(*protocolOptionState)) {
	if c == nil {
		return
	}
	v, ok := protocolOptionsState.Load(c)
	var st *protocolOptionState
	if ok {
		st, _ = v.(*protocolOptionState)
	}
	if st == nil {
		st = &protocolOptionState{}
		protocolOptionsState.Store(c, st)
	}
	mutate(st)
}

// BackchannelAllowsPrivateNetwork reports whether
// [WithBackchannelAllowPrivateNetwork] was invoked with a true
// argument against this config. The wiring layer (op.go) consults the
// accessor when constructing the back-channel deliverer so the
// per-config gate flows through to the SSRF check without forcing
// a [config]-struct field that the Option-side cannot reach from
// this file.
//
// The accessor is the only path through which the SSRF gate's
// inversion is exposed to the wiring layer; tests that need to
// observe the flag drive the option, not this method.
func (c *config) BackchannelAllowsPrivateNetwork() bool {
	return loadProtocolState(c).backchannelAllowPrivateNetwork
}

// WithBackchannelAllowPrivateNetwork suppresses the SSRF deny-list
// the back-channel logout deliverer applies to RP-controlled
// backchannel_logout_uri values. The default (option not invoked, or
// invoked with false) rejects loopback / link-local / RFC 1918 / IPv6
// ULA destinations so a hostile RP cannot register
// backchannel_logout_uri = "http://127.0.0.1/..." or
// "http://169.254.169.254/..." and have the OP POST a signed
// logout_token at an internal service.
//
// Embedders that front their RPs with private DNS — typical in
// service-mesh deployments where the RP and the OP share a pod
// network — opt in by passing true. The option flips the gate at
// the deliverer level only; nothing else in the SSRF posture changes
// (the JAR / JWKS fetcher is governed by the independent
// [WithAllowPrivateNetworkJWKS] / [WithAllowPrivateNetworkJAR]
// flags). The two surfaces are kept independent so an embedder can
// grant private-network access for one fetcher without widening the
// other.
//
// Stable since v0.x.
func WithBackchannelAllowPrivateNetwork(allow bool) Option {
	return optionFunc(func(c *config) error {
		mutateProtocolState(c, func(st *protocolOptionState) {
			st.backchannelAllowPrivateNetwork = allow
		})
		return nil
	})
}
