package op

import (
	"net/http"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/proxy"
)

// WithTrustedProxies declares the CIDRs from which the [Provider] should
// honour [X-Forwarded-*] headers. When a request arrives from outside these
// ranges the headers are ignored, preventing IP / scheme spoofing.
//
// X-Forwarded-Host hardening: when at least one CIDR is configured, the
// OP rejects an X-Forwarded-Host value whose hostname does not match the
// canonical issuer host or one of the entries supplied through
// [WithTrustedProxyHosts]. The default allowlist (the issuer host) is
// auto-derived so a typical single-hostname deployment requires no
// further configuration. An attacker who spoofs an arbitrary XFH on a
// connection arriving from a trusted CIDR cannot alias the OP onto a
// different host because the allowlist intersects the value with the
// canonical issuer.
//
// CIDRs may be IPv4 or IPv6; both notations are accepted. Each call
// replaces the previous list — pass every trusted CIDR in a single call.
// Stable since v1.0.
func WithTrustedProxies(cidrs ...string) Option {
	return optionFunc(func(c *config) error {
		if len(cidrs) == 0 {
			return newConfigurationError("WithTrustedProxies requires at least one CIDR", nil)
		}
		// Validate eagerly so misconfiguration surfaces at New time
		// rather than the first cross-proxy request.
		if _, err := proxy.NewTrust(cidrs); err != nil {
			return newConfigurationError("WithTrustedProxies CIDR rejected", err)
		}
		c.trustedProxies = append([]string(nil), cidrs...)
		return nil
	})
}

// WithTrustedProxyHosts adds hostnames the OP will honour in
// X-Forwarded-Host. The runtime allowlist is the union of the supplied
// hosts plus the canonical issuer host (auto-derived from [WithIssuer])
// so embedders that front their OP under a single public hostname need
// not call this option — the issuer host is allowlisted by default.
//
// Each host MUST be a non-empty string. Hostnames are compared
// case-insensitively against the value of X-Forwarded-Host (port
// stripped); IPv6 literals follow the bracketed RFC 7239 form. The
// option appends to any prior call so a deployment with multiple
// public hostnames can layer entries.
//
// Stable since v1.0.
func WithTrustedProxyHosts(hosts ...string) Option {
	return optionFunc(func(c *config) error {
		if len(hosts) == 0 {
			return newConfigurationError("WithTrustedProxyHosts requires at least one host", nil)
		}
		for _, h := range hosts {
			if strings.TrimSpace(h) == "" {
				return newConfigurationError("WithTrustedProxyHosts received an empty host", nil)
			}
		}
		c.trustedProxyHosts = append(c.trustedProxyHosts, hosts...)
		return nil
	})
}

// WithCORSOrigins adds explicit cross-origin entries to the CORS allowlist.
// The full allowlist is the union of these origins plus every redirect_uri
// origin the [store.ClientStore] returns; this option only handles entries
// that cannot be derived from a registered redirect_uri (admin SPAs,
// management consoles, etc.).
// Origins MUST be absolute URLs with non-empty scheme and host. The path,
// query, and fragment are stripped. Each call appends to the configured
// list; duplicates are deduplicated at allowlist build time.
// Stable since v1.0.
func WithCORSOrigins(origins ...string) Option {
	return optionFunc(func(c *config) error {
		if len(origins) == 0 {
			return newConfigurationError("WithCORSOrigins requires at least one origin", nil)
		}
		for _, o := range origins {
			if _, err := csrf.CanonicalOrigin(o); err != nil {
				return newConfigurationError("WithCORSOrigins origin rejected: "+o, err)
			}
		}
		c.corsOrigins = append(c.corsOrigins, origins...)
		return nil
	})
}

// WithBackchannelLogoutHTTPClient supplies the outbound Transport the
// back-channel logout coordinator uses when POSTing Logout Tokens to
// relying parties. Most embedders do not need this — the package
// default is correct for the spec posture.
//
// The coordinator copies only [http.Client.Transport]. It always applies
// [WithBackchannelLogoutTimeout], rejects redirects, and wraps the transport
// with URL-time and dial-time SSRF checks. This keeps instrumentation, proxy
// resolution, and custom dialers available without allowing a full client
// override to weaken delivery integrity.
// Stable since v1.0.
func WithBackchannelLogoutHTTPClient(client *http.Client) Option {
	return optionFunc(func(c *config) error {
		c.backchannelLogoutHTTPClient = client
		return nil
	})
}

// WithBackchannelLogoutTimeout caps the time the OP spends waiting
// for a single relying party to acknowledge a Logout Token POST. The
// budget applies per RP; the coordinator dispatches in parallel, so a
// slow RP does not delay deliveries to its peers.
// A zero or negative duration substitutes the package default
// (5 seconds). Embedders SHOULD keep the value low — back-channel
// logout is best-effort, and a long timeout merely keeps the OP
// holding state on a likely-broken RP.
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
// `bcl.no_sessions_for_subject` audit event ([AuditBCLNoSessionsForSubject])
// surfaces the gap when it actually fires. Declare the chosen
// posture through [WithSessionDurabilityPosture] so the audit
// signal carries the embedder's intent.
// Stable since v1.0.
func WithBackchannelLogoutTimeout(d time.Duration) Option {
	return optionFunc(func(c *config) error {
		c.backchannelLogoutTimeout = d
		return nil
	})
}

// SessionDurabilityPosture is the embedder's declaration of how
// [op/store.SessionStore] writes flow through their persistence
// tier. The choice is plumbed into the back-channel logout
// coordinator's `bcl.no_sessions_for_subject` audit event so SOC
// tooling can distinguish "expected gap under volatile placement"
// from "unexpected gap under durable placement" without keying on
// the store-adapter type. The library does not enforce the
// declaration; embedders who route SessionStore to a volatile
// backend while declaring [SessionDurabilityDurable] will see the
// audit event fire under conditions their dashboard's "durable"
// filter does not expect.
type SessionDurabilityPosture int

const (
	// SessionDurabilityVolatile is the default. SessionStore writes
	// are best-effort; eviction / failover may remove rows the
	// back-channel coordinator would walk. OIDC Back-Channel Logout
	// 1.0 §2.7 explicitly classifies delivery as best-effort, so
	// the volatile floor is spec-conformant — but the audit signal
	// makes the gap observable when it fires.
	SessionDurabilityVolatile SessionDurabilityPosture = iota

	// SessionDurabilityDurable declares that SessionStore writes
	// survive process restarts and tier failover. Embedders who
	// flip the declaration MUST route SessionStore to a durable
	// backend (the SQL adapter, an embedder-supplied store with
	// WAL semantics, etc.).
	SessionDurabilityDurable
)

// WithSessionDurabilityPosture records the embedder's declaration
// of [op/store.SessionStore] durability so the back-channel logout
// coordinator can stamp the value into the
// `bcl.no_sessions_for_subject` audit event ([AuditBCLNoSessionsForSubject]).
// The flag does not change runtime gates; it is a typed declaration
// that lets SOC dashboards filter expected gaps under volatile
// placement from unexpected gaps under durable placement.
//
// Default [SessionDurabilityVolatile]. Embedders who route
// SessionStore to a durable backend (the SQL adapter, an
// embedder-supplied store with WAL semantics) flip the declaration
// to [SessionDurabilityDurable].
// Stable since v1.0.
func WithSessionDurabilityPosture(p SessionDurabilityPosture) Option {
	return optionFunc(func(c *config) error {
		c.sessionDurabilityPosture = p
		return nil
	})
}

// WithDPoPNonceSource opts the provider into the RFC 9449 §8 / §9
// server-supplied nonce flow for DPoP proofs. With a non-nil source
// wired, the /token, /par, and /userinfo handlers reject any DPoP
// proof whose "nonce" claim is absent or not accepted by
// [DPoPNonceSource.Validate], emitting the spec-mandated
// `use_dpop_nonce` challenge along with a fresh value from
// [DPoPNonceSource.IssueNonce] in the response's `DPoP-Nonce`
// header.
// Without this option proofs without a nonce claim are accepted and
// the challenge is never emitted. The option is independent of [WithFeature]
// (feature.DPoP); the nonce flow only fires when DPoP is also
// enabled because the verifier itself is wired only on that flag.
// At most one source may be registered; a second [WithDPoPNonceSource]
// call fails [New] so a typo cannot silently win.
//
// Multi-replica deployments: the supplied [DPoPNonceSource] MUST be
// backed by a distributed cache (Redis / memcached / shared in-process
// gossip) when the OP runs behind more than one replica. A
// process-local source (e.g. the in-memory rotation ring shipped for
// development) issues nonces one replica accepts but the others
// reject, so a client routed across the fleet sees spurious
// `use_dpop_nonce` retries forever. The library deliberately ships no
// distributed implementation today; embedders supply one that matches
// their deployment topology.
// Stable since v1.0.
func WithDPoPNonceSource(source DPoPNonceSource) Option {
	return optionFunc(func(c *config) error {
		if isNilLike(source) {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDPoPNonceSource received nil DPoPNonceSource",
			}
		}
		if c.dpopNonces != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDPoPNonceSource may be called at most once",
			}
		}
		c.dpopNonces = source
		return nil
	})
}

// WithRefreshGracePeriod overrides the RFC 9700 §2.2.2 grace window
// the token endpoint applies to a replayed refresh token. Inside the
// window a parallel client retry that races the rotated child returns
// the same response without revoking the chain; outside it the
// replay is treated as theft and the family is revoked. The library
// default (60 seconds) absorbs typical SPA / mobile retry storms; a
// stricter posture passes a smaller positive duration. Pass zero to
// disable the window entirely so any replay revokes immediately —
// FAPI 2.0 §3.1.7 mandates this for FAPI2Baseline /
// FAPI2MessageSigning, and the option layer enforces the bound at
// construction time when those profiles are active (a non-zero value
// supplied alongside the profile produces a configuration error).
// Negative values are rejected at the option site; the API treats
// "no grace" as the explicit zero so accidental sign-flip cannot
// silently widen the window.
// Stable since v1.0.
func WithRefreshGracePeriod(d time.Duration) Option {
	return optionFunc(func(c *config) error {
		if d < 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithRefreshGracePeriod must not be negative",
			}
		}
		if c.refreshGracePeriodSet {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithRefreshGracePeriod may be called at most once",
			}
		}
		c.refreshGracePeriod = d
		c.refreshGracePeriodSet = true
		c.refreshGracePeriodIsZero = d == 0
		return nil
	})
}

// effectiveRefreshGrace returns the refresh-token grace window the
// token endpoint should apply. The function honours
// [WithRefreshGracePeriod] when called, else returns 0 so the internal
// exchanger falls back to its [refresh.GraceTTLDefault].
//
// A FAPI 2.0 profile is the exception: it resolves to a strict zero
// when the option is absent. FAPI 2.0 §3.1.7 forbids a replay-tolerant
// window for a replayed refresh token, and [New] already refuses an
// explicit non-zero one under that profile — so without this the
// profile would be honoured only for the embedder who asked for the
// wrong thing out loud, and silently violated for the one who said
// nothing, which is every deployment that simply declares the profile.
func (c *config) effectiveRefreshGrace() time.Duration {
	if !c.refreshGracePeriodSet {
		if c.hasFAPI2Profile() {
			return -1
		}
		return 0
	}
	if c.refreshGracePeriodIsZero {
		// Pass through as a negative sentinel so the internal
		// exchanger treats it as "explicit zero", not "use default".
		return -1
	}
	return c.refreshGracePeriod
}

// WithAllowPrivateNetworkJWKS suppresses the SSRF deny-list the
// internal JWKS fetcher applies to RP-controlled JWKS URIs. The
// default posture rejects URLs whose host is a literal "localhost",
// resolves to a loopback / link-local / RFC 1918 / ULA address, or
// uses a non-http(s) scheme; the OP does this so an attacker-
// controlled jwks_uri value cannot pivot the OP onto an internal
// service.
// Embedders that legitimately host their RPs on a private network
// (CI, on-prem deployment with an internal RP) opt in via this
// option. The opt-in is JWKS-specific so the analogous JAR
// request_uri fetcher remains independently gated by
// [WithAllowPrivateNetworkJAR].
// Stable since v1.0.
func WithAllowPrivateNetworkJWKS() Option {
	return optionFunc(func(c *config) error {
		c.allowPrivateNetworkJWKS = true
		return nil
	})
}

// WithAllowPrivateNetworkJAR is the JAR request_uri counterpart of
// [WithAllowPrivateNetworkJWKS]. It suppresses the SSRF deny-list
// applied to RP-controlled request_uri values when /authorize fetches
// the request object. The option is independent of the JWKS opt-in so
// embedders can grant private-network access to one fetcher without
// widening the other. The default false posture is the safe choice
// for production deployments.
// Stable since v1.0.
func WithAllowPrivateNetworkJAR() Option {
	return optionFunc(func(c *config) error {
		c.allowPrivateNetworkJAR = true
		return nil
	})
}

// WithAllowPrivateNetworkSector is the sector_identifier_uri
// counterpart of [WithAllowPrivateNetworkJWKS]. It suppresses the
// SSRF deny-list applied to the RP-controlled URI the OP fetches at
// dynamic client registration to validate the OIDC Core 1.0 §8.1
// pairwise subject sector. The option is independent of the JWKS and
// JAR opt-ins so an embedder can host the sector document on a
// private network without widening the other two fetchers. The
// default false posture is the safe choice for production
// deployments.
// Stable since v1.0.
func WithAllowPrivateNetworkSector() Option {
	return optionFunc(func(c *config) error {
		c.allowPrivateNetworkSector = true
		return nil
	})
}

// WithAllowLocalhostLoopback widens the RFC 8252 §7.3 native-app
// loopback redirect_uri carve-out to admit the textual "localhost"
// host. The default posture only admits the IP literals 127.0.0.1 and
// [::1] over plain http; localhost is rejected so a DNS-rebinding
// attacker (RFC 8252 §8.3) cannot point a registered
// http://localhost:* URI at a host they control after the client
// resolved it once. Native-app SDKs that bind their loopback listener
// to the textual "localhost" hostname (the most common default) opt
// in via this option.
//
// The option also admits "localhost" in the issuer itself. That half
// exists for WebAuthn: a Relying Party ID must be a domain and browsers
// reject an IP literal for it, so an http issuer on 127.0.0.1 has no
// valid RP ID to pair with and a local passkey deployment has nowhere to
// stand. The DNS-rebinding reasoning above does not stop applying — the
// carve-out is acceptable on a developer's machine and nowhere else.
//
// Many of the example demos under examples/ register
// http://127.0.0.1 redirect URIs and refuse to start without this
// opt-in; production embedders typically leave it off and instead
// front their RPs over https.
// Stable since v1.0.
func WithAllowLocalhostLoopback() Option {
	return optionFunc(func(c *config) error {
		c.allowLocalhostLoopback = true
		return nil
	})
}

// WithAllowInsecureBackchannelLogoutForDev is a dev / CI-only
// opt-out that admits plain-http loopback URLs for the
// `backchannel_logout_uri` client metadata field. The default
// posture rejects every non-https value at registration time
// (OpenID Connect Back-Channel Logout 1.0 §2.2), and the runtime
// SSRF gate refuses to POST a logout token at a loopback / private-
// network destination — both correct for production where the OP
// MUST reach RPs over the public Internet on TLS.
//
// The opt-in flips both gates ONLY for the loopback hosts
// 127.0.0.1, [::1], and "localhost". Public IP literals and
// non-loopback DNS names continue to require https; the SSRF
// gate's link-local / RFC 1918 / IPv6 ULA deny-list keeps every
// other private destination blocked. The option emits a loud
// audit-stream warning at op.New so a deployment cannot silently
// leave it on after promoting from CI to production.
//
// Use this option for the in-process demos under examples/ and for
// CI fixtures that bind a stub RP on a loopback port; never combine
// it with a non-development WithIssuer.
//
// Stable since v1.0.
func WithAllowInsecureBackchannelLogoutForDev() Option {
	return optionFunc(func(c *config) error {
		c.allowInsecureBackchannelLogoutForDev = true
		return nil
	})
}

// WithJWKSHTTPTransport injects an [http.RoundTripper] the OP uses
// when fetching RP-controlled JWKS endpoints. All three consumers take
// it: the signed request-object resolver (RFC 9101), the
// private_key_jwt client-assertion verifier (RFC 7523), and the
// outbound-encryption recipient resolver that turns a client's jwks_uri
// into the key an encrypted id_token / userinfo / JARM / introspection
// response is addressed to. They read the same endpoints, so a trust
// store one of them needs is one all of them need. The default
// nil leaves the library to construct a transport backed by Go's
// system trust store; embedders that front their RPs
// with an internal CA, or run the OP under a conformance harness
// with a self-signed runner cert, supply a transport with the
// matching TLSClientConfig.
//
// The supplied transport's DialContext is rewired by the package so
// the dial-time SSRF gate continues to fire — passing a custom
// transport widens trust, not the SSRF surface. The option is
// independent of [WithAllowPrivateNetworkJWKS] and
// [WithAllowPrivateNetworkJAR]; embedders typically pair it with one
// of those when their RP runs on a private network behind the
// internal CA.
//
// At most one transport may be registered; a second
// [WithJWKSHTTPTransport] call fails [New].
// Stable since v1.0.
func WithJWKSHTTPTransport(rt http.RoundTripper) Option {
	return optionFunc(func(c *config) error {
		if isNilLike(rt) {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithJWKSHTTPTransport received nil http.RoundTripper",
			}
		}
		if c.jwksHTTPTransport != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithJWKSHTTPTransport may be called at most once",
			}
		}
		c.jwksHTTPTransport = rt
		return nil
	})
}
