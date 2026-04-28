package jar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/timex"
)

// Default knobs for the JWKS fetcher. The values are chosen so a
// misbehaving client URL (slow, oversize, redirect loop) cannot stall
// the request thread or exhaust memory; embedders that need different
// posture configure the verifier with explicit overrides.
const (
	// defaultJWKSTimeout caps the total time spent fetching a JWKs
	// document, including connect, TLS, and body read. The HTTP
	// layer's per-request budget is independent; this limit guards
	// the verifier from a slowloris RP regardless of upstream
	// timeouts.
	defaultJWKSTimeout = 5 * time.Second

	// defaultJWKSMaxBody caps the JWKs body size at 256 KiB. Real
	// keysets are well under 4 KiB; the ceiling exists to bound
	// memory use against a malicious or misconfigured peer.
	defaultJWKSMaxBody = int64(256 * 1024)

	// defaultJWKSTTL is the in-memory cache TTL applied to a fetched
	// keyset when the upstream response carries no Cache-Control. The
	// value is short enough that a key rotation propagates without
	// operator intervention while saving most fetches.
	defaultJWKSTTL = 5 * time.Minute
)

// jwksCache is a tiny thread-safe TTL cache keyed by the JWKs URL. It
// stores the parsed keyset alongside the raw ETag (when the upstream
// emitted one) so the next refresh can issue a conditional request.
//
// The cache is intentionally small: a JAR-enabled OP serves a finite
// number of clients, and the entries are garbage-collectable once
// their expiry passes. An eviction policy is unnecessary at v0.x.
type jwksCache struct {
	mu      sync.RWMutex
	entries map[string]*jwksEntry
	clock   timex.Clock
}

// jwksEntry is the stored projection of one keyset. Keys is the parsed
// shape consumed by [Verifier.Verify]; ETag and Expiry let the fetcher
// short-circuit a network round-trip when a cached copy is still fresh.
type jwksEntry struct {
	keys   *josev4.JSONWebKeySet
	etag   string
	expiry time.Time
}

// newJWKSCache returns an initialised cache. A nil clock falls back to
// [timex.SystemClock] so tests that do not care about cache timing can
// pass nil.
func newJWKSCache(clock timex.Clock) *jwksCache {
	if clock == nil {
		clock = timex.SystemClock
	}
	return &jwksCache{
		entries: make(map[string]*jwksEntry),
		clock:   clock,
	}
}

// get returns the cached entry for url if it is still within its TTL.
// The boolean reports whether the caller may use the entry without a
// network round-trip; entries with an ETag past their TTL are still
// returned (with hit=false) so the caller can issue a conditional GET.
func (c *jwksCache) get(url string) (*jwksEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[url]
	if !ok {
		return nil, false
	}
	now := c.clock.Now()
	if now.Before(e.expiry) {
		return e, true
	}
	return e, false
}

// put records keys against url with the supplied ETag and TTL. A zero
// TTL falls back to [defaultJWKSTTL] so callers do not have to plumb
// the constant down.
func (c *jwksCache) put(url, etag string, keys *josev4.JSONWebKeySet, ttl time.Duration) {
	if ttl <= 0 {
		ttl = defaultJWKSTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[url] = &jwksEntry{
		keys:   keys,
		etag:   etag,
		expiry: c.clock.Now().Add(ttl),
	}
}

// httpJWKSFetcher is the production [JWKSResolver] backing
// [Verifier]. It enforces the SSRF deny-list, the timeout, the body
// cap, and the strict content-type check before handing parsed keys
// back to the verifier.
type httpJWKSFetcher struct {
	cache  *jwksCache
	client *http.Client

	// allowPrivate, when true, disables the SSRF deny-list. v0.x has
	// no public knob to flip this; the field exists so a future
	// op.WithAllowPrivateNetworkJWKS option can wire it through.
	allowPrivate bool
}

// newHTTPJWKSFetcher returns a fetcher with the project defaults
// applied. The supplied clock drives the cache; pass [timex.SystemClock]
// (or nil — the cache normalises) when the OP is not under test.
func newHTTPJWKSFetcher(clock timex.Clock) *httpJWKSFetcher {
	return &httpJWKSFetcher{
		cache: newJWKSCache(clock),
		client: &http.Client{
			Timeout: defaultJWKSTimeout,
		},
	}
}

// fetch retrieves the parsed keyset for jwksURI. The cache is consulted
// first; on a miss or expired entry the function performs the HTTP
// round-trip, applies the security checks, and updates the cache.
//
// The function is unexported because callers reach the JWKS through
// [Verifier]; exposing it would let a future caller bypass the SSRF /
// body-cap policy.
func (f *httpJWKSFetcher) fetch(ctx context.Context, jwksURI string) (*josev4.JSONWebKeySet, error) {
	if entry, ok := f.cache.get(jwksURI); ok {
		return entry.keys, nil
	}
	if err := f.assertSafeURL(jwksURI); err != nil {
		return nil, err
	}
	cached, _ := f.cache.get(jwksURI)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWKSFetch, err)
	}
	req.Header.Set("Accept", "application/json")
	if cached != nil && cached.etag != "" {
		req.Header.Set("If-None-Match", cached.etag)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWKSFetch, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if cached != nil && resp.StatusCode == http.StatusNotModified {
		// Bump expiry without re-parsing; the cached keyset is still
		// authoritative.
		f.cache.put(jwksURI, cached.etag, cached.keys, ttlFromResponse(resp))
		return cached.keys, nil
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%w: status %d", ErrJWKSFetch, resp.StatusCode)
	}
	if !isJSONContentType(resp.Header.Get("Content-Type")) {
		return nil, fmt.Errorf("%w: content-type %q is not JSON", ErrJWKSFetch, resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, defaultJWKSMaxBody+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %w", ErrJWKSFetch, err)
	}
	if int64(len(body)) > defaultJWKSMaxBody {
		return nil, fmt.Errorf("%w: body exceeds %d bytes", ErrJWKSFetch, defaultJWKSMaxBody)
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return nil, err
	}
	f.cache.put(jwksURI, resp.Header.Get("ETag"), keys, ttlFromResponse(resp))
	return keys, nil
}

// assertSafeURL rejects URLs whose host resolves to a loopback,
// link-local, or RFC 1918 address unless the fetcher was constructed
// with allowPrivate set. The check runs before the request is issued so
// an attacker-controlled JWKsURI cannot trick the OP into hitting an
// internal service.
//
// The fetcher only performs a syntactic / DNS-time check: a malicious
// upstream that resolves a public name to a private address at the
// last moment can still escape this gate. The HTTP client transport
// could be wrapped to enforce per-connection address checks; v0.x
// punts on that hardening because the JWKS fetcher already runs with
// a hard timeout.
//
// Embedders that front their RPs with private DNS can opt in by
// passing [AllowPrivateNetwork] to [NewDefaultResolver]; the
// public op-package alias is op.WithAllowPrivateNetworkJWKS.
func (f *httpJWKSFetcher) assertSafeURL(raw string) error {
	if f.allowPrivate {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: parse url: %w", ErrJWKSFetch, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("%w: scheme %q not allowed", ErrJWKSFetch, u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: missing host", ErrJWKSFetch)
	}
	if IsLocalHostname(host) {
		return fmt.Errorf("%w: host %q is loopback / localhost", ErrJWKSFetch, host)
	}
	if ip := net.ParseIP(host); ip != nil {
		if IsPrivateIP(ip) {
			return fmt.Errorf("%w: host %q is loopback / link-local / private", ErrJWKSFetch, host)
		}
		return nil
	}
	return f.assertResolvedHostSafe(host)
}

// assertResolvedHostSafe performs the DNS-time SSRF check. It is
// split out so [assertSafeURL] stays under the project complexity
// gate; the function uses [net.DefaultResolver.LookupIPAddr] (with
// a fresh context) because the project lint rule forbids the
// context-less [net.LookupIP] entry point.
func (f *httpJWKSFetcher) assertResolvedHostSafe(host string) error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultJWKSTimeout)
	defer cancel()
	addrs, lookupErr := net.DefaultResolver.LookupIPAddr(ctx, host)
	if lookupErr != nil {
		return fmt.Errorf("%w: lookup %q: %w", ErrJWKSFetch, host, lookupErr)
	}
	for _, addr := range addrs {
		if IsPrivateIP(addr.IP) {
			return fmt.Errorf("%w: host %q resolves to a private IP", ErrJWKSFetch, host)
		}
	}
	return nil
}

// IsLocalHostname reports whether host is a literal "localhost" string
// or one of its common variants. The check is case-insensitive because
// DNS is. The function is exported so the authorize-endpoint JAR
// request_uri fetcher reuses the same allow-list without the two
// packages drifting.
func IsLocalHostname(host string) bool {
	h := strings.ToLower(host)
	switch h {
	case "localhost", "localhost.", "ip6-localhost", "ip6-loopback":
		return true
	default:
		return false
	}
}

// IsPrivateIP reports whether ip falls inside one of the deny-listed
// ranges: loopback (127.0.0.0/8 + ::1), link-local (169.254.0.0/16 +
// fe80::/10), and the RFC 1918 / ULA private blocks. The list is
// closed; the [WithAllowPrivateNetwork] opt-in flips the gate at the
// fetcher level rather than poking holes in this check. Exported for
// the authorize-endpoint JAR request_uri fetcher to share.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	if ip.IsPrivate() {
		return true
	}
	return false
}

// isJSONContentType reports whether ct is a JSON-ish media type. JWKS
// servers vary: some emit "application/json", some "application/jwk-set+json"
// (RFC 7517 §8.5). Both are accepted; anything else (text/html from a
// captive portal, application/octet-stream) is rejected so a misrouted
// request cannot be parsed as JSON by accident.
func isJSONContentType(ct string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(strings.ToLower(ct))
	return ct == "application/json" || ct == "application/jwk-set+json"
}

// parseJWKS decodes body into a [josev4.JSONWebKeySet]. Empty keysets
// are accepted at this layer (an RP that publishes an empty set is
// returning a syntactically valid response); the verifier surfaces
// [ErrNoMatchingJWK] when no key matches the kid.
func parseJWKS(body []byte) (*josev4.JSONWebKeySet, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("%w: empty body", ErrJWKSFetch)
	}
	var keys josev4.JSONWebKeySet
	if err := json.Unmarshal(body, &keys); err != nil {
		return nil, fmt.Errorf("%w: parse jwks: %w", ErrJWKSFetch, err)
	}
	return &keys, nil
}

// ttlFromResponse extracts the freshness lifetime from the response
// headers. Cache-Control max-age beats a numeric Expires; both fall
// back to [defaultJWKSTTL] when absent. Negative or zero max-age also
// collapses to the default — JWKS docs are not safe to mark
// "no-cache" because revalidation against an unreachable upstream is
// indistinguishable from a key rotation.
func ttlFromResponse(resp *http.Response) time.Duration {
	if maxAge, ok := parseMaxAge(resp.Header.Get("Cache-Control")); ok && maxAge > 0 {
		return maxAge
	}
	return defaultJWKSTTL
}

// parseMaxAge pulls a numeric "max-age" directive out of a
// Cache-Control header value. The parser is intentionally minimal: it
// accepts the canonical form ("max-age=300") and ignores quoted forms
// or leading whitespace. Anything more elaborate is silently treated
// as absent so the caller falls back to the default TTL.
func parseMaxAge(cc string) (time.Duration, bool) {
	if cc == "" {
		return 0, false
	}
	for _, raw := range strings.Split(cc, ",") {
		token := strings.TrimSpace(strings.ToLower(raw))
		const prefix = "max-age="
		if !strings.HasPrefix(token, prefix) {
			continue
		}
		secs, err := parseUnsignedSeconds(token[len(prefix):])
		if err != nil {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	return 0, false
}

// parseUnsignedSeconds decodes a non-negative decimal integer, returning
// an error on any non-digit input. Used by [parseMaxAge] so the caller
// does not depend on strconv directly.
func parseUnsignedSeconds(s string) (int64, error) {
	if s == "" {
		return 0, errors.New("empty")
	}
	var out int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-digit %q", c)
		}
		out = out*10 + int64(c-'0')
		if out > 1<<31 {
			return 0, errors.New("overflow")
		}
	}
	return out, nil
}
