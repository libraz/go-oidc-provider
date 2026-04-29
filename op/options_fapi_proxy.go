package op

import (
	"net/netip"
	"sync"

	"github.com/libraz/go-oidc-provider/internal/mtls"
)

// WithMTLSProxy configures the reverse-proxy header path the OP
// consults for client certificates. The OP looks for the cert in
// [http.Request.TLS.PeerCertificates] first; only when no TLS
// handshake cert is present does it fall back to the header named by
// headerName, AND only when the request's RemoteAddr lies inside one
// of the trustedCIDRs ranges.
//
// The two-part requirement closes the symmetric spoofing vector
// behind H-FAPI-1: an attacker who reaches the OP directly (bypassing
// the reverse proxy) MUST NOT be able to forge a client certificate
// by setting the header. The OP fails closed on any untrusted source,
// returning the same wire response as a request without a cert.
//
// trustedCIDRs entries may be IPv4 / IPv6 CIDR notation
// ("10.0.0.0/8", "fd00::/8") or bare IP literals ("192.168.1.1");
// bare literals are promoted to host-mask prefixes (/32 or /128).
// Empty headerName disables the header path entirely; an empty
// trustedCIDRs slice rejects the option at construction time so a
// misconfiguration cannot silently widen the allow-list.
//
// Experimental — partial wiring: as of this revision, [New] validates
// the option and the mTLS verifier package honours the resulting
// allow-list when callers construct it directly through
// [internal/mtls.NewVerifier]. The op.go wiring layer that ships in
// the same release path will pick the recorded value up via
// [MTLSProxyConfig] in a follow-up; until that lands, embedders who
// need the runtime header path should construct the mtls.Verifier
// themselves and pass the recorded [mtls.ProxyConfig].
//
// Stable since v0.x (the input-validation surface; the wiring is
// experimental until the follow-up).
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
		mtlsProxyStore.Store(c, mtlsProxyState{
			header:  headerName,
			trusted: prefixes,
		})
		return nil
	})
}

// MTLSProxyConfig returns the [mtls.ProxyConfig] previously recorded
// through [WithMTLSProxy] on p. The returned value carries an empty
// HeaderName / TrustedProxies when the option was not configured —
// the embedder treats that as "header path disabled" and the
// verifier consults TLS-handshake certs only.
//
// The function is exported so an embedder running the partial-wiring
// transition can build the mtls.Verifier themselves and pass the
// recorded state forward.
func MTLSProxyConfig(p *Provider) mtls.ProxyConfig {
	if p == nil {
		return mtls.ProxyConfig{}
	}
	v, ok := mtlsProxyStore.Load(p.cfg)
	if !ok {
		return mtls.ProxyConfig{}
	}
	state, ok := v.(mtlsProxyState)
	if !ok {
		return mtls.ProxyConfig{}
	}
	return mtls.ProxyConfig{
		HeaderName:     state.header,
		TrustedProxies: append([]netip.Prefix(nil), state.trusted...),
	}
}

// mtlsProxyState is the recorded shape of [WithMTLSProxy]. The struct
// is package-private; embedders read the projection through
// [MTLSProxyConfig] so the storage shape can evolve without breaking
// callers.
type mtlsProxyState struct {
	header  string
	trusted []netip.Prefix
}

// mtlsProxyStore associates a [WithMTLSProxy] state with the
// [config] pointer the option was applied to. The sync.Map keying
// keeps the new option self-contained in this file (no field added
// to the existing config struct) at the cost of one map lookup at
// boot — the cost is one-time and the storage is freed when the
// Provider is garbage-collected.
//
//nolint:gochecknoglobals // small package-local registry; one entry per Provider construction.
var mtlsProxyStore sync.Map
