package mtls

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
)

// ProxyConfig describes how the OP locates the client certificate on an
// inbound request. The zero value enables only the direct-TLS path: a
// cert is consumed from [http.Request.TLS.PeerCertificates] when one is
// present, and the request is treated as un-authenticated otherwise.
//
// Deployments that terminate TLS at a reverse proxy MUST set
// [ProxyConfig.HeaderName] to the header the proxy uses to forward the
// PEM-encoded leaf cert (commonly "X-Client-Cert" or
// "Ssl-Client-Cert"). The header support is opt-in because admitting
// any header by default would let an attacker spoof a client cert
// merely by setting the header on a plain request.
type ProxyConfig struct {
	// HeaderName is the HTTP header carrying a URL-encoded PEM block
	// of the client cert. Empty disables the header path entirely;
	// only direct TLS handshakes can satisfy [CertificateFromRequest].
	//
	// Whether the header value is URL-encoded depends on the proxy.
	// Common deployments (nginx ssl_client_escaped_cert) emit
	// percent-encoded PEM with newlines preserved; the package
	// accepts both encoded and raw PEM by trying URL-decoding first
	// and falling back to the raw payload.
	HeaderName string
}

// CertificateFromRequest returns the leaf client certificate associated
// with r. The function checks two sources, in order:
//
//  1. The TLS handshake — when [http.Request.TLS] is non-nil and carries
//     at least one peer certificate, the leaf is returned verbatim.
//  2. The configured proxy header — when [ProxyConfig.HeaderName] is
//     non-empty and the request carries that header.
//
// The function returns [ErrNoClientCert] when neither source yields a
// cert and [ErrCertMalformed] when a header is present but its payload
// cannot be parsed. The caller maps the sentinel onto a wire status
// without inspecting the wrapped cause.
//
// Multi-cert headers (a chain rather than a leaf) are tolerated by
// reading only the first PEM block; subsequent blocks are intermediate
// CAs that the OP is not interested in for thumbprint binding.
func CertificateFromRequest(r *http.Request, cfg ProxyConfig) (*x509.Certificate, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil request", ErrNoClientCert)
	}
	if cert := certFromTLSHandshake(r); cert != nil {
		return cert, nil
	}
	if cfg.HeaderName == "" {
		return nil, ErrNoClientCert
	}
	raw := r.Header.Get(cfg.HeaderName)
	if raw == "" {
		return nil, ErrNoClientCert
	}
	return parseHeaderCert(raw)
}

// certFromTLSHandshake returns the leaf cert from the TLS handshake or
// nil when no cert is present. The function intentionally does NOT
// distinguish "TLS off" from "TLS on without cert"; both cases yield
// nil because they collapse to the same caller-visible behaviour
// (continue with the proxy header path or surface ErrNoClientCert).
func certFromTLSHandshake(r *http.Request) *x509.Certificate {
	if r.TLS == nil {
		return nil
	}
	if len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}

// parseHeaderCert decodes the PEM payload commonly forwarded by
// reverse proxies. The payload may be raw PEM (Apache SSLProxyVerify)
// or URL-encoded (nginx ssl_client_escaped_cert).
//
// The function tries the raw payload first because [url.QueryUnescape]
// silently rewrites "+" to " " — which would corrupt a base64 PEM
// payload that happens to contain "+" characters. URL-decoding is
// only attempted as a fallback when the raw payload does not contain
// a recognisable PEM block.
func parseHeaderCert(raw string) (*x509.Certificate, error) {
	if cert, err := decodePEMCert(raw); err == nil {
		return cert, nil
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: header payload contains no PEM block", ErrCertMalformed)
	}
	return decodePEMCert(decoded)
}

// decodePEMCert is the single-shot PEM → x509 path. It is split out so
// [parseHeaderCert] can attempt the raw and URL-decoded payloads in
// sequence without nesting decoder state.
func decodePEMCert(raw string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("%w: header payload contains no PEM block", ErrCertMalformed)
	}
	if block.Type != "" && block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%w: PEM block is %q, want CERTIFICATE", ErrCertMalformed, block.Type)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse DER: %w", ErrCertMalformed, err)
	}
	return cert, nil
}
