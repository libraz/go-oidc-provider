// Package proxy parses [X-Forwarded-*] headers when the request arrives from a
// trusted reverse proxy. The behaviour follows
// docs/plans/002-product-design.md §F.5: untrusted requests fall back to
// [http.Request.RemoteAddr] so a hostile client cannot spoof its source IP or
// scheme by injecting headers.
//
// The package operates on raw values (CIDR strings, RemoteAddr strings) so it
// does not depend on the rest of the OIDC stack and can be unit-tested in
// isolation.
package proxy

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// Trust is an immutable, concurrency-safe set of trusted proxy CIDRs that
// determines whether [X-Forwarded-*] headers may be honoured. The zero value is
// usable and rejects every header — equivalent to "no proxy configured".
type Trust struct {
	cidrs []netip.Prefix
}

// NewTrust parses the supplied CIDR strings and returns an immutable [Trust]
// value. An empty input yields a trust that rejects every forwarded header,
// which is the safe default when running without a reverse proxy.
//
// CIDRs may be IPv4 or IPv6 in standard "prefix/length" notation. Empty
// strings are rejected so configuration mistakes surface at startup rather
// than silently widening the trust boundary.
func NewTrust(cidrs []string) (*Trust, error) {
	if len(cidrs) == 0 {
		return &Trust{}, nil
	}
	parsed := make([]netip.Prefix, 0, len(cidrs))
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return nil, errors.New("proxy: trusted CIDR must not be empty")
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("proxy: invalid CIDR %q: %w", raw, err)
		}
		parsed = append(parsed, p.Masked())
	}
	return &Trust{cidrs: parsed}, nil
}

// IsConfigured reports whether the trust has at least one CIDR. It is exposed
// so the caller can emit the start-up WARNING required by §F.5 when the trust
// is empty but the deployment is presumed to be behind a proxy.
func (t *Trust) IsConfigured() bool { return t != nil && len(t.cidrs) > 0 }

// Contains reports whether the given remote address (as parsed by [Parse])
// falls inside any configured CIDR.
func (t *Trust) Contains(addr netip.Addr) bool {
	if t == nil {
		return false
	}
	for _, p := range t.cidrs {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Resolved holds the values derived from a request once forwarded headers have
// been considered. ClientIP is always populated; Scheme falls back to the
// scheme on the [http.Request] URL when no trusted forwarding is in effect.
type Resolved struct {
	// ClientIP is the address considered authoritative for the request.
	ClientIP netip.Addr

	// Scheme is the request scheme that should be honoured for security
	// decisions (cookie Secure flag, HSTS, redirect_uri scheme matching).
	Scheme string

	// Host is the host header that should be used for issuer / discovery
	// URL validation. May be empty if the request and headers omit it.
	Host string

	// Trusted reports whether the request came from a CIDR in the trust
	// list. When false, forwarded headers were ignored.
	Trusted bool
}

// Resolve inspects r and t to produce a [Resolved] view of the request.
//
// Behaviour matrix (§F.5):
//
//   - Trust empty                       → forwarded headers ignored, scheme
//     comes from r.URL/r.TLS, ClientIP from r.RemoteAddr.
//   - Trust set, RemoteAddr ∉ trust     → forwarded headers ignored, audit
//     callers should log proxy.untrusted.
//   - Trust set, RemoteAddr ∈ trust     → walk X-Forwarded-For from right to
//     left, return the first value outside the trust as the client IP, and
//     honour X-Forwarded-Proto / X-Forwarded-Host.
func Resolve(r *http.Request, t *Trust) Resolved {
	res := Resolved{
		Scheme: requestScheme(r),
		Host:   r.Host,
	}
	remote, ok := parseRemoteAddr(r.RemoteAddr)
	if ok {
		res.ClientIP = remote
	}
	if !t.IsConfigured() || !ok || !t.Contains(remote) {
		return res
	}
	res.Trusted = true
	if ip, ok := walkForwardedFor(r.Header.Values("X-Forwarded-For"), t); ok {
		res.ClientIP = ip
	}
	if scheme := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); scheme != "" {
		res.Scheme = strings.ToLower(scheme)
	}
	if host := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); host != "" {
		res.Host = host
	}
	return res
}

// parseRemoteAddr strips the optional ":port" suffix from r.RemoteAddr and
// parses the result as a [netip.Addr]. It tolerates IPv6 literals wrapped in
// brackets as written by net/http.
func parseRemoteAddr(remote string) (netip.Addr, bool) {
	if remote == "" {
		return netip.Addr{}, false
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// walkForwardedFor returns the first address in the X-Forwarded-For chain
// (read right-to-left) that does not fall inside the trust. This is the RFC
// 7239 §5.2 algorithm and prevents a client from spoofing its IP by writing
// fake values to the left of the chain.
func walkForwardedFor(values []string, t *Trust) (netip.Addr, bool) {
	for i := len(values) - 1; i >= 0; i-- {
		for j := len(values[i]); j > 0; {
			comma := strings.LastIndexByte(values[i][:j], ',')
			token := strings.TrimSpace(values[i][comma+1 : j])
			j = comma
			if token == "" {
				continue
			}
			addr, err := netip.ParseAddr(token)
			if err != nil {
				return netip.Addr{}, false
			}
			addr = addr.Unmap()
			if !t.Contains(addr) {
				return addr, true
			}
		}
	}
	return netip.Addr{}, false
}

// requestScheme derives the scheme directly from the request, ignoring any
// X-Forwarded-Proto header. The forwarded value is layered on top by
// [Resolve] only after the trust check succeeds.
func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if r.URL != nil && r.URL.Scheme != "" {
		return r.URL.Scheme
	}
	return "http"
}
