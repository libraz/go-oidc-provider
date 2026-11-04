package op

import (
	"net/netip"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/op/feature"
)

// WithMTLSProxy configures the reverse-proxy header path the OP
// consults for client certificates. When the request arrives from a
// trusted source — its RemoteAddr lies inside one of the
// [MTLSProxy.TrustedProxies] ranges — the cert forwarded in the header
// named by [MTLSProxy.HeaderName] is authoritative and takes precedence
// over any TLS-handshake cert. On a dual-mTLS / mesh hop the internal
// handshake carries the proxy's OWN transport cert while the header
// carries the real OAuth client's cert. These identify different
// principals and are never compared: transport authentication of the
// proxy belongs to the embedder's HTTP server, while the OP binds
// RFC 8705 credentials to the forwarded client cert. Requests from any
// other source ignore the header entirely and fall back to the direct
// TLS-handshake cert.
//
// The trusted-source requirement closes the symmetric spoofing vector:
// an attacker who reaches the OP directly (bypassing the reverse proxy)
// MUST NOT be able to forge a client certificate by setting the header.
// The OP fails closed on any untrusted source, returning the same wire
// response as a request without a cert.
//
// TrustedProxies entries may be IPv4 / IPv6 CIDR notation
// ("10.0.0.0/8", "fd00::/8") or bare IP literals ("192.168.1.1");
// bare literals are promoted to host-mask prefixes (/32 or /128). An
// empty TrustedProxies falls back to the CIDRs given to
// [WithTrustedProxies], so one allow-list can serve both the forwarded
// client address and the forwarded certificate; [New] fails when both
// are empty, so a misconfiguration cannot silently widen the allow-list.
// An empty HeaderName is rejected at the option site (omit the option to
// disable the header path).
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
// [Provider.MTLSProxy] reads the effective value back so embedder-side
// middleware can be pinned to the same allow-list.
//
// The verifier that consumes the allow-list exists only when
// [feature.MTLS] is enabled, so [New] fails when this option is set
// without WithFeature(feature.MTLS): a forwarded certificate would
// otherwise be ignored and access tokens issued as plain bearer tokens
// with no cnf.x5t#S256 confirmation.
//
// The recorded state lives on the [Provider]'s own configuration
// (not a package-level registry), so two [Provider] instances never
// share or leak each other's proxy configuration, and the state is
// collected along with the Provider once it becomes unreachable.
//
// Stable since v1.0.
func WithMTLSProxy(p MTLSProxy) Option {
	return optionFunc(func(c *config) error {
		if err := c.claimOnce("WithMTLSProxy"); err != nil {
			return err
		}
		if p.HeaderName == "" {
			return newConfigurationError("WithMTLSProxy: MTLSProxy.HeaderName must not be empty (omit the option to disable the header path)", nil)
		}
		c.mtlsProxy = mtlsProxyState{
			header:  p.HeaderName,
			trusted: slices.Clone(p.TrustedProxies),
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
// It is the argument of [WithMTLSProxy] and the value
// [Provider.MTLSProxy] reads back, so embedder code can name it,
// declare variables of it, and build one directly (for edge middleware
// that must strip the same header from untrusted sources, say).
//
// Stable since v1.1.
type MTLSProxy struct {
	// HeaderName is the HTTP header the trusted proxy forwards the
	// client certificate in. Empty disables the header path.
	HeaderName string

	// TrustedProxies lists the CIDR ranges (or bare IP literals) the
	// header is honoured from. As an option argument, empty means "use
	// the [WithTrustedProxies] CIDRs"; as a read-back value it is the
	// effective list in CIDR notation.
	TrustedProxies []string
}

// MTLSProxy returns the effective [MTLSProxy] the OP enforces: the
// header name and the trusted CIDRs after the [WithTrustedProxies]
// fallback, in CIDR notation. The result is the zero value when
// [WithMTLSProxy] was not configured — the verifier then consults
// TLS-handshake certs only. A nil Provider also returns the zero value.
//
// TrustedProxies is a fresh slice on every call, so a caller that
// appends to it cannot widen the allow-list the [Provider] enforces.
//
// The accessor exists so embedder-side code that has to agree with the
// OP about which hop may forward a client certificate — an edge
// middleware that strips the header, a reverse-proxy health check, an
// out-of-band resource server — can read the configured allow-list back
// rather than duplicating the literal CIDR list.
func (p *Provider) MTLSProxy() MTLSProxy {
	if p == nil {
		return MTLSProxy{}
	}
	header, prefixes, err := p.cfg.effectiveMTLSProxy()
	if err != nil || header == "" {
		return MTLSProxy{}
	}
	out := MTLSProxy{HeaderName: header, TrustedProxies: make([]string, len(prefixes))}
	for i, pre := range prefixes {
		out.TrustedProxies[i] = pre.String()
	}
	return out
}

// effectiveMTLSProxy resolves the [WithMTLSProxy] state against
// [WithTrustedProxies]: it returns the header and the parsed prefixes
// the verifier enforces. Both values are zero when the option was not
// configured. It fails when the resolved allow-list is empty or holds an
// unparsable entry.
func (c *config) effectiveMTLSProxy() (string, []netip.Prefix, error) {
	if c == nil || c.mtlsProxy.header == "" {
		return "", nil, nil
	}
	cidrs := c.mtlsProxy.trusted
	if len(cidrs) == 0 {
		cidrs = c.trustedProxies
	}
	if len(cidrs) == 0 {
		return "", nil, newConfigurationError("WithMTLSProxy: MTLSProxy.TrustedProxies is empty and WithTrustedProxies is not set; "+
			"admit only the proxy(ies) that strip and rewrite the cert header", nil)
	}
	prefixes, err := mtls.ParseTrustedProxies(cidrs)
	if err != nil {
		return "", nil, newConfigurationError("WithMTLSProxy: TrustedProxies rejected", err)
	}
	return c.mtlsProxy.header, prefixes, nil
}

// mtlsProxyConfig projects the effective [WithMTLSProxy] state onto the
// verifier's configuration. The zero value means the header path is off.
func (c *config) mtlsProxyConfig() (mtls.ProxyConfig, error) {
	header, prefixes, err := c.effectiveMTLSProxy()
	if err != nil {
		return mtls.ProxyConfig{}, err
	}
	return mtls.ProxyConfig{HeaderName: header, TrustedProxies: prefixes}, nil
}

// validateMTLSOptions refuses mTLS settings that the OP would never read.
// [buildMTLSVerifier] returns a nil verifier unless [feature.MTLS] is
// enabled, and every consumer reads nil as "mTLS off": a configured
// [WithMTLSProxy] allow-list or [WithMTLSRootCAs] pool would be ignored
// and tokens would be issued as plain bearer tokens while the
// configuration says they are certificate-bound. It also resolves the
// [WithMTLSProxy] allow-list so an empty one fails here.
func (c *config) validateMTLSOptions() error {
	if !featureEnabled(c.features, feature.MTLS) {
		for _, o := range []struct {
			configured bool
			option     string
		}{
			{c.mtlsProxy.header != "", "WithMTLSProxy"},
			{c.mtlsRootCAs != nil, "WithMTLSRootCAs"},
		} {
			if o.configured {
				return newConfigurationError(o.option+" is configured but the mTLS feature is not enabled, so the "+
					"OP builds no certificate verifier and would never read the value: client certificates "+
					"would be ignored and access tokens issued as plain bearer tokens with no cnf.x5t#S256 "+
					"confirmation. Add WithFeature(feature.MTLS), or drop "+o.option, nil)
			}
		}
	}
	_, _, err := c.effectiveMTLSProxy()
	return err
}

// mtlsProxyState is the recorded shape of [WithMTLSProxy], carried on
// [config.mtlsProxy]: the header name and the explicit CIDR strings,
// before the [WithTrustedProxies] fallback. The struct is package-private;
// embedders read the effective value through [Provider.MTLSProxy].
type mtlsProxyState struct {
	header  string
	trusted []string
}
