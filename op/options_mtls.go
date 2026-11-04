package op

import (
	"crypto/x509"
)

// WithMTLSRootCAs installs the trust anchors the OP validates client
// certificates against before it uses them for RFC 8705 §3 token
// binding or §2.1 tls_client_auth client authentication. The pool is
// consulted by the OP's own mTLS verifier on
// every request that carries a client certificate, whichever source it
// came from: the TLS handshake, or the forwarded header configured by
// [WithMTLSProxy].
//
// The option is independent of, and complementary to, the TLS
// termination the embedder already performs:
//
//   - A direct-TLS deployment normally validates the chain in
//     [crypto/tls.Config.ClientCAs] during the handshake. Passing the
//     same pool here is redundant but harmless.
//   - A reverse-proxy deployment validates the chain at the proxy and
//     forwards the leaf in a header. The OP cannot see that
//     validation, so a pool here is the only way to make the OP
//     re-check the chain itself — useful when the proxy is configured
//     to forward optional / unverified client certificates.
//
// A certificate that does not chain to the pool — including one that
// lacks the clientAuth extended key usage or has expired, both of which
// the standard library checks while building the chain — makes the
// request fail (invalid_client at the token endpoint). It is not
// silently downgraded to an unbound bearer token, so a misissued
// certificate surfaces at the request that presented it rather than
// producing a token nobody expected to be unbound.
//
// tls_client_auth admits only a chain-verified certificate. Over direct
// TLS the handshake's verified chains suffice; a forwarded certificate is
// verified only by this pool, so [New] fails when tls_client_auth is
// reachable through [WithMTLSProxy] without it.
//
// The pool does not apply to a client registered for
// self_signed_tls_client_auth. Its certificate authenticates by matching a
// key in the client's jwks / jwks_uri (RFC 8705 §2.2) and is bound to its
// tokens as cnf.x5t#S256 without a chain check, at /token and wherever the
// binding is re-verified. A forwarded certificate still has to arrive from
// a [WithMTLSProxy] trusted source. Every other client, tls_client_auth or
// any method using certificate-bound tokens, stays under the pool.
//
// Leave the option unset (the default) when TLS termination — direct
// or at a trusted proxy — has already validated the client chain and no
// tls_client_auth client sits behind a proxy. A
// nil pool is rejected at construction: [x509.NewCertPool] with no
// certificate added is the way to express "trust nothing", and
// accepting nil here would silently mean "trust whatever the transport
// gave us", the opposite of the caller's evident intent.
//
// The pool is consumed by the mTLS verifier, which only exists when
// [feature.MTLS] is enabled. Without that flag there is no
// certificate-binding path for the anchors to govern, so [New] fails
// rather than let the pool go unread while access tokens are issued as
// plain bearer tokens. Pair the option with WithFeature(feature.MTLS).
//
// Stable since v1.1.
func WithMTLSRootCAs(pool *x509.CertPool) Option {
	return optionFunc(func(c *config) error {
		if err := c.claimOnce("WithMTLSRootCAs"); err != nil {
			return err
		}
		if pool == nil {
			return newConfigurationError("WithMTLSRootCAs: pool must not be nil (omit the option to leave chain validation to the TLS terminator)", nil)
		}
		c.mtlsRootCAs = pool
		return nil
	})
}

// mtlsRootCAsPool returns the trust anchors recorded by [WithMTLSRootCAs],
// or nil when the option was not configured. The accessor exists so
// the verifier builder reads the same shape it does for every other
// mTLS knob.
func (c *config) mtlsRootCAsPool() *x509.CertPool {
	if c == nil {
		return nil
	}
	return c.mtlsRootCAs
}
