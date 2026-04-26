package mtls

import (
	"crypto/x509"
	"net/http"
)

// Verifier is the request-scoped entry point used by the token and
// userinfo handlers. It is constructed once at startup with
// [NewVerifier] and is safe for concurrent use; it merely caches the
// [ProxyConfig] so handlers do not have to thread it through every
// call site.
//
// The shape mirrors [internal/dpop.Verifier] on purpose: a non-nil
// pointer is the "feature is enabled" signal everywhere the HTTP
// layer touches it, and a nil receiver is never expected (callers
// gate on the field's nilness before invoking any method).
type Verifier struct {
	proxy ProxyConfig
}

// VerifierConfig is the parameter bundle for [NewVerifier]. The struct
// is in place even though the verifier currently only carries a
// [ProxyConfig] so future fields (a CA pool, a per-deployment
// thumbprint algorithm override) can be added without churning every
// call site.
type VerifierConfig struct {
	// Proxy is the reverse-proxy configuration consulted when a
	// request did not terminate TLS at the OP. The zero value
	// disables the header path entirely.
	Proxy ProxyConfig
}

// NewVerifier returns a [*Verifier] from cfg. It never fails because
// no field is currently mandatory; the (*Verifier, error) signature is
// preserved so wiring code at op/op.go can mirror the [dpop.NewVerifier]
// shape and so future required fields can be enforced without a
// signature break.
//
//nolint:unparam // error return reserved for future required fields.
func NewVerifier(cfg VerifierConfig) (*Verifier, error) {
	return &Verifier{proxy: cfg.Proxy}, nil
}

// CertificateFromRequest is the request-scoped wrapper around the
// package-level [CertificateFromRequest] function: it threads the
// stored [ProxyConfig] so callers do not have to.
func (v *Verifier) CertificateFromRequest(r *http.Request) (*x509.Certificate, error) {
	return CertificateFromRequest(r, v.proxy)
}

// ThumbprintFromRequest returns the RFC 8705 §3.1 thumbprint of the
// request's client cert. It is the high-level entry point the token
// endpoint uses at issuance: the thumbprint goes into cnf.x5t#S256 on
// the issued access token AND onto the persisted refresh-token
// record so subsequent refresh requests can re-verify the binding.
//
// Returns "" with no error when no cert is presented and the
// [ProxyConfig] disables (or does not name) a header — the caller
// interprets that as "issue a bearer token".
//
// Returns "" with [ErrCertMalformed] when a header IS present but its
// payload is not parseable: the request claimed an mTLS binding it
// could not back up, so the caller emits invalid_request.
func (v *Verifier) ThumbprintFromRequest(r *http.Request) (string, error) {
	cert, err := v.CertificateFromRequest(r)
	if err != nil {
		// Distinguish "no cert at all" (which is fine on the bearer
		// path) from "cert payload malformed" (which is a wire
		// fault). The caller switches on the sentinel.
		return "", err
	}
	return Thumbprint(cert), nil
}

// VerifyBoundRequest enforces an existing cnf.x5t#S256 binding on
// requests. The caller passes the bound thumbprint extracted from the
// access token / refresh-token record; the function locates the
// request's client cert, computes its thumbprint, and returns nil
// when the two match.
//
// The error taxonomy is distinct from [ThumbprintFromRequest]:
//   - [ErrNoClientCert] when the request does not present any cert
//     while the token claims a binding;
//   - [ErrCertMalformed] when a header is present but unparseable;
//   - [ErrThumbprintMismatch] when a cert IS present but the digest
//     differs from boundThumbprint.
//
// All three sentinels collapse onto the same wire response
// (invalid_token at /userinfo, invalid_grant at /token) so the
// granularity is for logs, not the client.
func (v *Verifier) VerifyBoundRequest(r *http.Request, boundThumbprint string) error {
	if boundThumbprint == "" {
		// Defensive: a zero binding should not have reached this
		// helper. Fail closed because silently admitting any cert
		// would defeat the §3.2 contract.
		return ErrThumbprintMismatch
	}
	cert, err := v.CertificateFromRequest(r)
	if err != nil {
		return err
	}
	got := Thumbprint(cert)
	if got == "" || got != boundThumbprint {
		return ErrThumbprintMismatch
	}
	return nil
}
