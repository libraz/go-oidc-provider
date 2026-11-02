package op

import (
	"strings"

	"github.com/libraz/go-oidc-provider/internal/nilcheck"
	"github.com/libraz/go-oidc-provider/internal/ssf"
	"github.com/libraz/go-oidc-provider/op/store"
)

// ssfScopePrefix is the scope namespace the SSF transmitter owns; see
// [WithSharedSignals].
const ssfScopePrefix = "ssf."

// WithSharedSignals turns the OP into a Shared Signals Framework 1.0
// transmitter. Receivers are OAuth clients of this OP: one obtains an
// access token through client_credentials with the ssf.read or
// ssf.manage scope, configures one stream at the configuration
// endpoint, and receives CAEP / RISC Security Event Tokens (RFC 8417)
// by push (RFC 8935) or poll (RFC 8936). The OP registers both scopes
// itself (Public: false); which clients may request them is decided by
// each client's registered scopes.
//
// An event about a subject reaches a receiver only when the subject
// holds a grant for the receiver's client. The OP emits CAEP
// session-revoked on its own when an RP-Initiated Logout destroys a
// session and when [Provider.RevokeSubject] runs; every other event is
// reported by the embedder through [Provider.EmitSecurityEvent].
//
// [New] requires the store to implement [store.SharedSignalsStore] with
// non-nil SSFStreams and SSFEvents substores, Store.Grants() to
// implement [store.GrantClientLister], and [WithCookieKeys] (the key ring
// a push stream's authorization_header is sealed under). Scope names
// starting with "ssf." are reserved: [New] refuses one registered
// through [WithScope] while the transmitter is on.
// A push worker runs in the background from [New] until
// [Provider.Shutdown].
//
// Stable since v1.5.
func WithSharedSignals() Option {
	return optionFunc(func(c *config) error {
		c.sharedSignals = true
		return nil
	})
}

// WithAllowPrivateNetworkSharedSignals admits RFC 1918 / IPv6 ULA push
// endpoints for SSF receivers, the counterpart of
// [WithAllowPrivateNetworkBackchannel]. The default refuses them so a
// receiver cannot aim signed SETs at an internal service. Cloud metadata
// addresses stay refused whatever the value.
//
// This is network reach for deployments whose relying parties live on a
// private network; it is legitimate in production, not a development-only
// option, and [New] logs one INFO line naming what it widens. Repeating
// the option is a no-op.
//
// Stable since v1.5.
func WithAllowPrivateNetworkSharedSignals() Option {
	return optionFunc(func(c *config) error {
		c.sharedSignalsAllowPrivateNetwork = true
		return nil
	})
}

// WithAllowInsecureSharedSignalsPushForDev admits http:// and loopback
// push endpoints for SSF receivers, the counterpart of
// [WithAllowInsecureBackchannelLogoutForDev]. Production push endpoints
// MUST be https on a public address. [New] refuses the option unless the
// issuer is a development host: a loopback IP literal, "localhost", or a
// name under the RFC 6761 special-use TLDs .localhost, .test, .invalid
// or .example.
//
// Stable since v1.5.
func WithAllowInsecureSharedSignalsPushForDev() Option {
	return optionFunc(func(c *config) error {
		c.allowInsecureSharedSignalsPushForDev = true
		return nil
	})
}

// validateSharedSignals enforces the [WithSharedSignals] construction
// contract. The ssf. scope prefix is refused only while the transmitter
// is on, so a deployment that never enables it keeps its scope names.
func (c *config) validateSharedSignals() error {
	if c.allowInsecureSharedSignalsPushForDev && !isDevelopmentIssuer(c.issuer) {
		return newConfigurationError(
			"WithAllowInsecureSharedSignalsPushForDev requires a development issuer (loopback, localhost, or a .localhost/.test/.invalid/.example host)", nil,
		)
	}
	if !c.sharedSignals {
		return nil
	}
	for _, s := range c.scopes {
		if strings.HasPrefix(s.Name, ssfScopePrefix) {
			return newConfigurationError(
				"WithScope: the "+ssfScopePrefix+" scope prefix is reserved for WithSharedSignals ("+s.Name+")", nil,
			)
		}
	}
	if _, err := c.sharedSignalsStore(); err != nil {
		return err
	}
	if _, err := c.sharedSignalsGrants(); err != nil {
		return err
	}
	if len(c.cookieKeys) == 0 {
		return newConfigurationError(
			"WithSharedSignals requires WithCookieKeys: push authorization headers are sealed under the cookie key ring", nil,
		)
	}
	return nil
}

// sharedSignalsGrants returns the grant store as the client lister the
// transmitter reads, or the configuration error naming what is missing.
func (c *config) sharedSignalsGrants() (store.GrantClientLister, error) {
	grants, ok := c.store.Grants().(store.GrantClientLister)
	if !ok || nilcheck.IsNil(grants) {
		return nil, newConfigurationError(
			"WithSharedSignals requires Store.Grants() to implement store.GrantClientLister", nil,
		)
	}
	return grants, nil
}

// sharedSignalsStore returns the store's SSF substores, or the
// configuration error naming what is missing.
func (c *config) sharedSignalsStore() (store.SharedSignalsStore, error) {
	ss, ok := c.store.(store.SharedSignalsStore)
	if !ok {
		return nil, newConfigurationError(
			"WithSharedSignals requires the store to implement store.SharedSignalsStore", nil,
		)
	}
	if nilcheck.IsNil(ss.SSFStreams()) || nilcheck.IsNil(ss.SSFEvents()) {
		return nil, newConfigurationError(
			"WithSharedSignals requires non-nil SSFStreams() and SSFEvents() substores", nil,
		)
	}
	return ss, nil
}

// registerSharedSignalsScopes appends the receiver scopes to the
// configured set when the transmitter is on. It runs after
// [config.validateSharedSignals] refused any embedder scope in the
// prefix, so the names cannot be duplicated.
func (c *config) registerSharedSignalsScopes() {
	if !c.sharedSignals {
		return
	}
	c.scopes = append(c.scopes,
		Scope{Name: ssf.ScopeRead, Public: false},
		Scope{Name: ssf.ScopeManage, Public: false},
	)
}
