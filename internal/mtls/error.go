package mtls

import "errors"

// Sentinel errors returned by the package. Callers MUST branch on these
// via [errors.Is]; string-matching the wrapped cause is forbidden
// because the wrapped error originates in third-party x509 / JOSE
// machinery whose wording is not stable across versions.
//
// The HTTP layer maps these onto wire codes (RFC 8705 §3 prescribes
// "invalid_token" at the resource server and "invalid_client" at the
// token endpoint) rather than echoing the wrapped cause, so the
// surface visible to the client stays opaque while logs retain full
// diagnostic detail via [errors.Unwrap].
var (
	// ErrNoClientCert signals that the request did not present a
	// client certificate: neither a TLS handshake leaf nor a trusted
	// reverse-proxy header. The HTTP layer maps this onto a 401
	// challenge for resource calls and onto invalid_client at the
	// token endpoint.
	ErrNoClientCert = errors.New("mtls: no client certificate presented")

	// ErrCertMalformed signals that a presented cert could not be
	// parsed. Typical causes are a header that does not contain a
	// PEM block, a corrupted DER blob inside the PEM, or a header
	// the embedder configured but a downstream proxy rewrote.
	ErrCertMalformed = errors.New("mtls: client certificate malformed")

	// ErrCertUntrusted signals that a presented cert did not verify
	// against the verifier's configured RootCAs. Only emitted when
	// [VerifierConfig.RootCAs] is non-nil; deployments that rely on
	// TLS/proxy chain validation can leave RootCAs unset.
	ErrCertUntrusted = errors.New("mtls: client certificate is not trusted")

	// ErrCertSourceConflict is retained for compatibility with HTTP-layer
	// error mapping but is no longer emitted by certificate source selection.
	// On a trusted-proxy path, a TLS handshake leaf identifies the proxy
	// transport while the forwarded leaf identifies the OAuth client, so
	// differing thumbprints are expected and are not a source conflict.
	ErrCertSourceConflict = errors.New("mtls: client certificate sources disagree")

	// ErrSubjectMismatch signals that the client cert's subject DN
	// did not equal the value registered against the client (RFC
	// 8705 §2.1.2). Only emitted on the tls_client_auth path.
	ErrSubjectMismatch = errors.New("mtls: certificate subject does not match")

	// ErrSANMismatch signals that none of the configured SAN
	// matchers matched a value present on the cert (RFC 8705 §2.1.2).
	// Only emitted on the tls_client_auth path.
	ErrSANMismatch = errors.New("mtls: certificate SAN does not match")

	// ErrNoMatcherConfigured signals that the client metadata required
	// for the tls_client_auth check is empty: the OP cannot decide
	// whether the cert is acceptable without at least one of the
	// subject_dn / san_* fields. Treated as a configuration fault by
	// the caller, which surfaces invalid_client.
	ErrNoMatcherConfigured = errors.New("mtls: client has no tls_client_auth matcher configured")

	// ErrAmbiguousMatcher signals that more than one tls_client_auth
	// matcher field is set. RFC 8705 §2.1.2 requires exactly one, so the
	// registration is refused and a stored record carrying several fails
	// closed at the token endpoint.
	ErrAmbiguousMatcher = errors.New("mtls: more than one tls_client_auth matcher configured")

	// ErrMatcherMalformed signals a matcher value that cannot be compared,
	// such as a tls_client_auth_san_ip that is not an IP literal.
	ErrMatcherMalformed = errors.New("mtls: tls_client_auth matcher malformed")

	// ErrCertChainUnverified signals that a certificate presented for
	// tls_client_auth was not chain-validated: neither the TLS handshake
	// nor [VerifierConfig.RootCAs] verified it. RFC 8705 §2.1 PKI
	// authentication never admits such a certificate.
	ErrCertChainUnverified = errors.New("mtls: client certificate chain was not verified")

	// ErrNoMatchingJWK signals that the self-signed client cert's
	// public-key thumbprint does not appear in the client's
	// registered JWKS (RFC 8705 §2.2.2). The matcher only inspects
	// the public-key thumbprints because the spec deliberately avoids
	// requiring the OP to validate the signature on the cert itself.
	ErrNoMatchingJWK = errors.New("mtls: no JWK matches the presented certificate")

	// ErrJWKSMalformed signals that the supplied JWKS bytes are not
	// a valid JSON Web Key Set. Used by the self_signed path when the
	// embedder's [Client.JWKS] field cannot be parsed, which covers
	// both an undecodable document and a well-formed one whose every
	// member uses a key type this build cannot represent (individual
	// undecodable members are skipped, see
	// [VerifySelfSignedTLSClientAuth]).
	ErrJWKSMalformed = errors.New("mtls: JWKS could not be parsed")

	// ErrThumbprintMismatch signals that the cert presented at a
	// resource endpoint produces a different "x5t#S256" thumbprint
	// than the one bound to the access token (RFC 8705 §3.2). The
	// HTTP layer maps this onto invalid_token.
	ErrThumbprintMismatch = errors.New("mtls: certificate thumbprint does not match the bound value")

	// ErrUnsupportedMethod signals that the supplied
	// token_endpoint_auth_method names neither tls_client_auth nor
	// self_signed_tls_client_auth. The dispatcher [VerifyClientAuth]
	// returns this so the HTTP layer can surface invalid_client
	// without admitting a cert under an unrecognised policy.
	ErrUnsupportedMethod = errors.New("mtls: unsupported token_endpoint_auth_method")
)
