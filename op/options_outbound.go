package op

import "strconv"

// OutboundTarget names one class of outbound HTTP request the OP makes on
// behalf of a relying party or a receiver, and so the fetch whose SSRF
// deny-list [WithAllowPrivateNetwork] lifts. The set is closed: the
// constants below are the only valid values, and an options call that
// receives anything else fails [New].
//
// Stable since v1.5.
type OutboundTarget uint8

const (
	// OutboundJWKS is the fetch of a relying party's jwks_uri. It covers
	// the client-assertion verifier, the signed request-object resolver
	// and the outbound-encryption recipient resolver.
	OutboundJWKS OutboundTarget = iota + 1

	// OutboundJAR is the fetch of a request_uri request object at
	// /authorize (RFC 9101).
	OutboundJAR

	// OutboundSector is the fetch of a sector_identifier_uri document at
	// dynamic client registration (OpenID Connect Core 1.0 §8.1).
	OutboundSector

	// OutboundClientIDMetadata is the fetch of a client ID metadata
	// document named by a client_id URL. The document's jwks_uri is a
	// separate fetch governed by [OutboundJWKS].
	//
	// Experimental: tracks an IETF draft, so the target MAY change in a
	// minor release on a wire-incompatible draft bump.
	OutboundClientIDMetadata

	// OutboundBackchannel is the delivery of a back-channel logout token
	// to a relying party's backchannel_logout_uri.
	OutboundBackchannel

	// OutboundSharedSignals is the push delivery of security event tokens
	// to a shared-signals receiver's endpoint.
	OutboundSharedSignals
)

// String returns the Go identifier of t, for example "OutboundJWKS".
func (t OutboundTarget) String() string {
	switch t {
	case OutboundJWKS:
		return "OutboundJWKS"
	case OutboundJAR:
		return "OutboundJAR"
	case OutboundSector:
		return "OutboundSector"
	case OutboundClientIDMetadata:
		return "OutboundClientIDMetadata"
	case OutboundBackchannel:
		return "OutboundBackchannel"
	case OutboundSharedSignals:
		return "OutboundSharedSignals"
	default:
		return "OutboundTarget(" + strconv.Itoa(int(t)) + ")"
	}
}

// privateNetworkOption spells the [WithAllowPrivateNetwork] call that
// lifts the deny-list of t, as the refusal errors and startup log lines
// quote it so the operator knows what to set.
func privateNetworkOption(t OutboundTarget) string {
	return "WithAllowPrivateNetwork(op." + t.String() + ")"
}

// WithAllowPrivateNetwork suppresses the SSRF deny-list for the listed
// outbound fetches. The default posture rejects a URL whose host is a
// literal "localhost", resolves to a loopback / link-local / RFC 1918 /
// ULA address, or uses a non-http(s) scheme; the OP does this so an
// attacker-controlled URL value cannot pivot it onto an internal service.
// Cloud metadata addresses stay refused whatever the value.
//
// This is network reach for deployments whose relying parties live on a
// private network (on-prem, service mesh, internal RPs); it is legitimate
// in production, not a development-only option. Each target is lifted
// independently, so private-network access granted to one fetch never
// widens another, and a call lists only the targets it means to open:
//
//   - [OutboundJWKS]: a relying party's jwks_uri.
//   - [OutboundJAR]: a request_uri request object.
//   - [OutboundSector]: a sector_identifier_uri document.
//   - [OutboundClientIDMetadata]: a client ID metadata document; it also
//     admits the http scheme for client_id URLs.
//   - [OutboundBackchannel]: back-channel logout delivery.
//   - [OutboundSharedSignals]: shared-signals push delivery.
//
// [New] logs one line per listed target naming what it widens: INFO, or
// WARN when open dynamic registration or Client ID Metadata Documents is
// enabled too and the target's URL can be chosen by an unauthenticated
// caller (SSRF exposure).
//
// An empty target list or an unknown value fails [New]. The option may be
// repeated; the targets of all calls are united, and listing a target
// twice is a no-op.
//
// Stable since v1.5.
func WithAllowPrivateNetwork(targets ...OutboundTarget) Option {
	return optionFunc(func(c *config) error {
		if len(targets) == 0 {
			return newConfigurationError("WithAllowPrivateNetwork requires at least one OutboundTarget", nil)
		}
		for _, t := range targets {
			if !t.valid() {
				return newConfigurationError("WithAllowPrivateNetwork: unknown "+t.String(), nil)
			}
		}
		for _, t := range targets {
			c.allowPrivateNetwork(t)
		}
		return nil
	})
}

// valid reports whether t is one of the declared targets.
func (t OutboundTarget) valid() bool {
	return t >= OutboundJWKS && t <= OutboundSharedSignals
}

// allowPrivateNetwork records the private-network opt-in of t.
func (c *config) allowPrivateNetwork(t OutboundTarget) {
	switch t {
	case OutboundJWKS:
		c.allowPrivateNetworkJWKS = true
	case OutboundJAR:
		c.allowPrivateNetworkJAR = true
	case OutboundSector:
		c.allowPrivateNetworkSector = true
	case OutboundClientIDMetadata:
		c.allowPrivateNetworkCIMD = true
	case OutboundBackchannel:
		c.backchannelAllowPrivateNetwork = true
	case OutboundSharedSignals:
		c.sharedSignalsAllowPrivateNetwork = true
	}
}

// WithAllowInsecureOutboundForDev is a dev / CI-only opt-out that admits
// plain-http and loopback destinations for the listed outbound deliveries.
// Production deliveries MUST be https to a public address; this option
// exists so in-process demos and CI fixtures can POST at a stub receiver
// bound to a loopback port.
//
// Only two targets accept it:
//
//   - [OutboundBackchannel] admits plain-http loopback URLs for the
//     backchannel_logout_uri client metadata field, which the default
//     posture rejects at registration time (OpenID Connect Back-Channel
//     Logout 1.0 §2.2), and releases the runtime SSRF gate for loopback
//     destinations only. The hosts are 127.0.0.1, [::1] and "localhost",
//     the last only while it resolves to a loopback address, so a
//     split-horizon resolver cannot widen the opt-in. Public IP literals
//     and non-loopback DNS names continue to require https, and the
//     link-local / RFC 1918 / IPv6 ULA deny-list keeps every other private
//     destination blocked. Reaching an RP on a private LAN is a different
//     decision with a different option:
//     [WithAllowPrivateNetwork] with [OutboundBackchannel].
//   - [OutboundSharedSignals] admits http:// and loopback push endpoints
//     for shared-signals receivers.
//
// Any other target, an empty list, or an unknown value fails [New]. The
// option may be repeated; the targets of all calls are united.
//
// [New] refuses the option unless the issuer is a development host: a
// loopback IP literal, "localhost", or a name under the RFC 6761
// special-use TLDs .localhost, .test, .invalid or .example. It logs a
// warning per listed target on the operational logger and records the
// opt-in on the audit stream, as insecure_backchannel_logout_for_dev and
// insecure_shared_signals_push_for_dev on the [AuditStartupProfile]
// event, so a deployment cannot silently leave it on after promoting from
// CI to production.
//
// Stable since v1.5.
func WithAllowInsecureOutboundForDev(targets ...OutboundTarget) Option {
	return optionFunc(func(c *config) error {
		if len(targets) == 0 {
			return newConfigurationError("WithAllowInsecureOutboundForDev requires at least one OutboundTarget", nil)
		}
		var backchannel, sharedSignals bool
		for _, t := range targets {
			switch t {
			case OutboundBackchannel:
				backchannel = true
			case OutboundSharedSignals:
				sharedSignals = true
			default:
				return newConfigurationError("WithAllowInsecureOutboundForDev accepts only OutboundBackchannel and "+
					"OutboundSharedSignals, got "+t.String(), nil)
			}
		}
		c.allowInsecureBackchannelLogoutForDev = c.allowInsecureBackchannelLogoutForDev || backchannel
		c.allowInsecureSharedSignalsPushForDev = c.allowInsecureSharedSignalsPushForDev || sharedSignals
		return nil
	})
}

// insecureOutboundOption spells the [WithAllowInsecureOutboundForDev] call
// for t, as refusal errors and startup log lines quote it.
func insecureOutboundOption(t OutboundTarget) string {
	return "WithAllowInsecureOutboundForDev(op." + t.String() + ")"
}
