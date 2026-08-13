package op

import (
	"net/netip"

	"github.com/libraz/go-oidc-provider/internal/mtls"
)

// WithMTLSProxy configures the reverse-proxy header path the OP
// consults for client certificates. When the request arrives from a
// trusted source — its RemoteAddr lies inside one of the trustedCIDRs
// ranges — the cert forwarded in the header named by headerName is
// authoritative and takes precedence over any TLS-handshake cert. On a
// dual-mTLS / mesh hop the internal handshake carries the proxy's OWN
// transport cert while the header carries the real OAuth client's cert.
// These identify different principals and are never compared: transport
// authentication of the proxy belongs to the embedder's HTTP server,
// while the OP binds RFC 8705 credentials to the forwarded client cert.
// Requests from any other source ignore the header entirely and fall
// back to the direct TLS-handshake cert.
//
// The trusted-source requirement closes the symmetric spoofing vector:
// an attacker who reaches the OP directly (bypassing the reverse proxy)
// MUST NOT be able to forge a client certificate by setting the header.
// The OP fails closed on any untrusted source, returning the same wire
// response as a request without a cert.
//
// trustedCIDRs entries may be IPv4 / IPv6 CIDR notation
// ("10.0.0.0/8", "fd00::/8") or bare IP literals ("192.168.1.1");
// bare literals are promoted to host-mask prefixes (/32 or /128).
// Empty headerName disables the header path entirely; an empty
// trustedCIDRs slice rejects the option at construction time so a
// misconfiguration cannot silently widen the allow-list.
//
// Every trusted proxy MUST strip the named header from the inbound
// request and replace it only after validating the external client
// certificate. The OP accepts exactly one header field containing one
// raw or percent-encoded CERTIFICATE PEM block; duplicate values, PEM
// chains, and trailing non-whitespace data are rejected as malformed.
//
// Wiring: [New] validates the option and threads the resulting
// allow-list into the OP's mTLS verifier so the reverse-proxy header
// path is honoured for every request handled by the [Provider].
// [MTLSProxyConfig] reads the recorded value back as an [MTLSProxy]
// so embedder-side middleware can be pinned to the same allow-list.
//
// The verifier that consumes the allow-list exists only when
// [feature.MTLS] is enabled. Without that flag this option is recorded
// and validated but never read: certificates in the forwarded header
// are ignored and access tokens carry no cnf.x5t#S256 confirmation,
// even though [MTLSProxyConfig] still reads the configured value back.
// [New] logs a partial-wiring warning in that case rather than failing,
// so a deployment that stages the allow-list ahead of the flag keeps
// booting. Pair the option with WithFeature(feature.MTLS).
//
// The recorded state lives on the [Provider]'s own configuration
// (not a package-level registry), so two [Provider] instances never
// share or leak each other's proxy configuration, and the state is
// collected along with the Provider once it becomes unreachable.
//
// Stable since v1.0.
func WithMTLSProxy(headerName string, trustedCIDRs []string) Option {
	return optionFunc(func(c *config) error {
		if headerName == "" {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithMTLSProxy: headerName must not be empty (omit the option to disable the header path)",
			}
		}
		if len(trustedCIDRs) == 0 {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithMTLSProxy: trustedCIDRs must not be empty; admit only the proxy(ies) that strip and rewrite the cert header",
			}
		}
		prefixes, err := mtls.ParseTrustedProxies(trustedCIDRs)
		if err != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithMTLSProxy: trustedCIDRs rejected",
				Cause:       err,
			}
		}
		c.mtlsProxy = mtlsProxyState{
			header:  headerName,
			trusted: prefixes,
		}
		return nil
	})
}

// MTLSProxy describes where the OP looks for a client certificate on
// an inbound request: the header a trusted reverse proxy forwards the
// PEM-encoded leaf in, and the CIDR ranges the OP is willing to honour
// that header from. The zero value means "header path disabled" — only
// a certificate from the TLS handshake is considered.
//
// The type is the public name for the value [WithMTLSProxy] records
// and [MTLSProxyConfig] reads back, so embedder code can name it,
// declare variables of it, and build one directly (for edge middleware
// that must strip the same header from untrusted sources, say).
//
// Stable since v1.1.
type MTLSProxy = mtls.ProxyConfig

// MTLSProxyConfig returns the [MTLSProxy] previously recorded through
// [WithMTLSProxy] on p. The returned value carries an empty
// HeaderName / TrustedProxies when the option was not configured —
// the embedder treats that as "header path disabled" and the
// verifier consults TLS-handshake certs only.
//
// TrustedProxies is a fresh slice on every call, so a caller that
// appends to it cannot widen the allow-list the [Provider] enforces.
//
// The function is exported so embedder-side code that has to agree
// with the OP about which hop may forward a client certificate — an
// edge middleware that strips the header, a reverse-proxy health
// check, an out-of-band resource server — can read the configured
// allow-list back rather than duplicating the literal CIDR list.
func MTLSProxyConfig(p *Provider) MTLSProxy {
	if p == nil {
		return MTLSProxy{}
	}
	return loadMTLSProxyConfig(p.cfg)
}

// loadMTLSProxyConfig reads the [WithMTLSProxy] state recorded on cfg
// and projects it into a fresh [MTLSProxy]. Returns the zero value
// when [WithMTLSProxy] was not called.
func loadMTLSProxyConfig(cfg *config) MTLSProxy {
	if cfg == nil {
		return MTLSProxy{}
	}
	state := cfg.mtlsProxy
	if state.header == "" && len(state.trusted) == 0 {
		return MTLSProxy{}
	}
	return MTLSProxy{
		HeaderName:     state.header,
		TrustedProxies: append([]netip.Prefix(nil), state.trusted...),
	}
}

// mtlsProxyState is the recorded shape of [WithMTLSProxy], carried on
// [config.mtlsProxy]. The struct is package-private; embedders read
// the projection through [MTLSProxyConfig] so the storage shape can
// evolve without breaking callers.
type mtlsProxyState struct {
	header  string
	trusted []netip.Prefix
}
