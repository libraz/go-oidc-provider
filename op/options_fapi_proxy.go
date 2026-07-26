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
// Embedders who construct an [internal/mtls.Verifier] themselves can
// still pass the recorded value via [MTLSProxyConfig].
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

// MTLSProxyConfig returns the [mtls.ProxyConfig] previously recorded
// through [WithMTLSProxy] on p. The returned value carries an empty
// HeaderName / TrustedProxies when the option was not configured —
// the embedder treats that as "header path disabled" and the
// verifier consults TLS-handshake certs only.
//
// The function is exported so embedders that construct an
// [internal/mtls.Verifier] themselves (e.g., for an out-of-band
// introspection endpoint) can reuse the same allow-list configured
// for the [Provider].
func MTLSProxyConfig(p *Provider) mtls.ProxyConfig {
	if p == nil {
		return mtls.ProxyConfig{}
	}
	return loadMTLSProxyConfig(p.cfg)
}

// loadMTLSProxyConfig reads the [WithMTLSProxy] state recorded on cfg
// and projects it into a fresh [mtls.ProxyConfig]. Returns the zero
// value when [WithMTLSProxy] was not called.
func loadMTLSProxyConfig(cfg *config) mtls.ProxyConfig {
	if cfg == nil {
		return mtls.ProxyConfig{}
	}
	state := cfg.mtlsProxy
	if state.header == "" && len(state.trusted) == 0 {
		return mtls.ProxyConfig{}
	}
	return mtls.ProxyConfig{
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
