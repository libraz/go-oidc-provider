package mtls

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/netip"
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
// "Ssl-Client-Cert") AND populate [ProxyConfig.TrustedProxies] with
// the CIDRs the OP is willing to accept the header from. The header
// support is opt-in because admitting any header by default would let
// an attacker spoof a client cert merely by setting the header on a
// plain request; the trusted-proxy allow-list closes the symmetric
// vector where an attacker reaches the OP directly (bypassing the
// proxy) and forges the header on a connection the OP would otherwise
// have honoured.
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

	// TrustedProxies is the set of [netip.Prefix] ranges the OP
	// accepts the cert header from. A request whose [http.Request.RemoteAddr]
	// does not parse to an IP inside one of these prefixes is treated
	// as a direct client connection and the configured header — even
	// when set — is ignored. Empty MUST be paired with an empty
	// [ProxyConfig.HeaderName]; a HeaderName configured without any
	// TrustedProxies surfaces as a configuration error at
	// [CertificateFromRequest] (the function returns
	// [ErrNoClientCert] so an embedder that bypassed the construction-
	// time guard does not silently honour spoofed headers).
	//
	// IPv4 and IPv6 prefixes are both accepted; mix freely. Use
	// [ParseTrustedProxies] to project a string CIDR list onto this
	// shape at construction time.
	TrustedProxies []netip.Prefix
}

// ParseTrustedProxies projects a string CIDR slice onto the
// [ProxyConfig.TrustedProxies] shape. The function rejects every
// malformed entry with a wrapped error so the embedder fails fast at
// startup; callers MUST NOT silently drop bad entries because that
// would erode the allow-list to the empty set and the runtime would
// honour spoofed headers.
//
// IPv4 / IPv6 mixed input is accepted. A single IP without a mask is
// accepted and treated as a /32 (IPv4) or /128 (IPv6) prefix so the
// embedder may pin a single proxy without computing the CIDR mask.
func ParseTrustedProxies(cidrs []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(cidrs))
	for i, raw := range cidrs {
		p, err := parsePrefixOrAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("mtls: TrustedProxies[%d] = %q: %w", i, raw, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// parsePrefixOrAddr handles both "10.0.0.0/8" and bare "10.0.0.1"
// inputs. The bare form is promoted to a host-mask prefix because
// embedders frequently pin a single proxy and forcing them to spell
// "/32" or "/128" only adds friction without changing the semantics.
func parsePrefixOrAddr(raw string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(raw); err == nil {
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("not a CIDR or IP literal: %w", err)
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	p, err := addr.Prefix(bits)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("derive host prefix: %w", err)
	}
	return p, nil
}

// CertificateFromRequest returns the leaf client certificate associated
// with r. The source it trusts depends on whether the deployment wired
// a reverse-proxy forwarding header:
//
//   - Direct-TLS deployment ([ProxyConfig.HeaderName] empty): the TLS
//     handshake leaf ([http.Request.TLS.PeerCertificates][0]) is the only
//     trusted source. This is the default and is left byte-for-byte
//     unchanged from a handshake-only implementation.
//   - Reverse-proxy deployment ([ProxyConfig.HeaderName] set AND
//     [http.Request.RemoteAddr] inside one of [ProxyConfig.TrustedProxies]):
//     the FORWARDED cert in the configured header is authoritative and
//     takes precedence over any handshake leaf. On a dual-mTLS / mesh hop
//     the internal handshake carries the proxy's OWN client cert while the
//     header carries the real client cert; binding to the handshake leaf
//     would silently collapse the sender-constraint to the proxy. When
//     both a handshake leaf and a forwarded cert are present and their
//     thumbprints disagree, the function returns [ErrCertSourceConflict]
//     rather than picking a source.
//
// A header from an untrusted source (RemoteAddr outside the allow-list)
// is ignored even when present; the direct handshake leaf, if any, is
// returned and otherwise the function yields [ErrNoClientCert] so the
// caller cannot distinguish "no header" from "untrusted header" through
// the wire response. A [ProxyConfig.HeaderName] configured without any
// [ProxyConfig.TrustedProxies] disables the header path entirely (fail
// closed): falling back to "trust every source" would defeat the §3.1
// binding contract by letting any client forge the header.
//
// The function returns [ErrNoClientCert] when no source yields a cert and
// [ErrCertMalformed] when a header is present, the source is trusted, but
// the payload cannot be parsed. The caller maps the sentinel onto a wire
// status without inspecting the wrapped cause.
//
// Multi-cert headers (a chain rather than a leaf) are tolerated by
// reading only the first PEM block; subsequent blocks are intermediate
// CAs that the OP is not interested in for thumbprint binding.
func CertificateFromRequest(r *http.Request, cfg ProxyConfig) (*x509.Certificate, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: nil request", ErrNoClientCert)
	}
	handshake := certFromTLSHandshake(r)
	// Header-path precedence is gated strictly on (HeaderName configured
	// AND the immediate peer is a trusted proxy). Both conditions must
	// hold so a direct-TLS deployment (HeaderName empty) keeps the
	// handshake-only behaviour exactly.
	if headerPathActive(r, cfg) {
		return certFromTrustedHeader(r, cfg, handshake)
	}
	if handshake != nil {
		return handshake, nil
	}
	// Either no header is configured, or a header is configured but the
	// request did not arrive from a trusted proxy (allow-list empty or
	// RemoteAddr outside it), so the header is ignored to stop a direct
	// client from spoofing a cert. Both collapse onto "no client cert".
	return nil, ErrNoClientCert
}

// headerPathActive reports whether the forwarded-cert header is both
// configured and admissible for this request: a non-empty
// [ProxyConfig.HeaderName], a non-empty [ProxyConfig.TrustedProxies]
// allow-list, and an [http.Request.RemoteAddr] inside that allow-list.
// The direct-TLS default (empty HeaderName) always returns false so the
// handshake-only path stays untouched.
func headerPathActive(r *http.Request, cfg ProxyConfig) bool {
	if cfg.HeaderName == "" {
		return false
	}
	if len(cfg.TrustedProxies) == 0 {
		return false
	}
	return remoteIsTrusted(r.RemoteAddr, cfg.TrustedProxies)
}

// certFromTrustedHeader resolves the client cert for a request that
// arrived from a trusted proxy with a forwarding header configured. The
// forwarded cert is authoritative; the handshake leaf (when present) is
// only consulted to detect a source conflict.
//
// An absent header yields [ErrNoClientCert]: the client presented no cert
// to the proxy, and any handshake leaf here belongs to the proxy itself
// (mesh / dual mTLS) and MUST NOT be bound. A handshake leaf that
// disagrees with the forwarded cert yields [ErrCertSourceConflict].
func certFromTrustedHeader(r *http.Request, cfg ProxyConfig, handshake *x509.Certificate) (*x509.Certificate, error) {
	raw := r.Header.Get(cfg.HeaderName)
	if raw == "" {
		return nil, ErrNoClientCert
	}
	headerCert, err := parseHeaderCert(raw)
	if err != nil {
		return nil, err
	}
	if handshake != nil && Thumbprint(handshake) != Thumbprint(headerCert) {
		return nil, ErrCertSourceConflict
	}
	return headerCert, nil
}

// remoteIsTrusted reports whether remoteAddr lies inside any of the
// configured prefixes. The function silently returns false for
// malformed inputs because [http.Request.RemoteAddr] is set by the
// std-library transport and a parse failure means the OP is fronting
// a non-IP transport (Unix socket, in-process pipe) where the header
// path is never legitimate anyway.
func remoteIsTrusted(remoteAddr string, prefixes []netip.Prefix) bool {
	addr, ok := parseRemoteAddr(remoteAddr)
	if !ok {
		return false
	}
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// parseRemoteAddr extracts the IP from an [http.Request.RemoteAddr]
// value. The std library typically formats the field as "host:port"
// (with IPv6 zones bracketed); the helper tolerates both shapes.
func parseRemoteAddr(remoteAddr string) (netip.Addr, bool) {
	if remoteAddr == "" {
		return netip.Addr{}, false
	}
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr // remoteAddr already a bare IP literal.
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
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
