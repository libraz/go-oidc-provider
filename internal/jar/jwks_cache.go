package jar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"golang.org/x/sync/singleflight"

	"github.com/libraz/go-oidc-provider/internal/netsec"
	"github.com/libraz/go-oidc-provider/internal/securefetch"
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

	// defaultJWKSNegativeTTL caps how long a fetch failure is cached
	// against a URL. The negative cache exists to defeat amplification
	// DoS: an attacker who repeatedly drives /authorize with a JAR
	// that names an unreachable jwks_uri would otherwise issue one
	// outbound request per inbound request. 30 seconds is long enough
	// to absorb a flood without delaying recovery from a transient RP
	// outage by more than half a minute.
	defaultJWKSNegativeTTL = 30 * time.Second
)

// jwksCache is a tiny thread-safe TTL cache keyed by the JWKs URL. It
// stores the parsed keyset alongside the raw ETag (when the upstream
// emitted one) so the next refresh can issue a conditional request.
//
// The cache is intentionally small: a JAR-enabled OP serves a finite
// number of clients, and the entries are garbage-collectable once
// their expiry passes. An eviction policy is unnecessary at v0.x.
type jwksCache struct {
	mu       sync.RWMutex
	entries  map[string]*jwksEntry
	failures map[string]*jwksFailure
	clock    timex.Clock
}

// jwksEntry is the stored projection of one keyset. Keys is the parsed
// shape consumed by [Verifier.Verify]; ETag and Expiry let the fetcher
// short-circuit a network round-trip when a cached copy is still fresh.
type jwksEntry struct {
	keys   *josev4.JSONWebKeySet
	etag   string
	expiry time.Time
}

// jwksFailure is the negative-cache entry. The cache stores the most
// recent error so callers see a stable diagnostic across the negative
// window (rather than retrying and observing a different transient
// failure on each call).
type jwksFailure struct {
	err    error
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
		entries:  make(map[string]*jwksEntry),
		failures: make(map[string]*jwksFailure),
		clock:    clock,
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
// the constant down. A successful put clears any negative-cache entry
// against the same URL so the recovery is observable on the next
// caller without waiting for the negative TTL to expire.
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
	delete(c.failures, url)
}

// putFailure records err against url for negativeTTL. Subsequent
// fetches against the same URL within the window short-circuit on the
// stored error, defeating amplification DoS against an unreachable
// upstream.
func (c *jwksCache) putFailure(url string, err error, ttl time.Duration) {
	if ttl <= 0 {
		ttl = defaultJWKSNegativeTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failures[url] = &jwksFailure{
		err:    err,
		expiry: c.clock.Now().Add(ttl),
	}
}

// getFailure returns the cached failure for url if it is still within
// its TTL. The boolean reports whether the caller MUST short-circuit
// on the stored error rather than reach out again.
func (c *jwksCache) getFailure(url string) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	f, ok := c.failures[url]
	if !ok {
		return false, nil
	}
	if c.clock.Now().Before(f.expiry) {
		return true, f.err
	}
	return false, nil
}

// Fetcher fetches a JWKs document from a remote URL with caching,
// singleflight collapsing, SSRF deny-list, body cap, and strict
// content-type check. It is the production resolver behind
// [Verifier] AND the JWKS source for client-assertion verification
// in [internal/clientauth] when a client registers a jwks_uri.
type Fetcher struct {
	cache  *jwksCache
	flight singleflight.Group

	// clientOnce / clientFetch wire the lazy [*securefetch.Client]
	// construction so callers can flip [allowPrivate] (or the base
	// transport) after [NewFetcher] returned but before the first
	// fetch without re-allocating the client on every fetch.
	clientOnce  sync.Once
	clientFetch *securefetch.Client

	// allowPrivate, when true, disables the SSRF deny-list (with the
	// exception of cloud-metadata IPs, which remain rejected via
	// [internal/netsec]).
	allowPrivate bool

	// baseTransport overrides the [http.RoundTripper] backing the lazy
	// client. Production wiring leaves this nil so [securefetch.NewClient]
	// installs its own [http.Transport]; embedders that need a custom
	// trust store (private CA, dev conformance harness with a
	// self-signed cert) inject one here. The dial-time SSRF gate is
	// still applied because [securefetch] re-wires DialContext on the
	// supplied transport before returning.
	baseTransport http.RoundTripper
}

// NewFetcher returns a fetcher with the project defaults applied.
// The supplied clock drives the cache; pass [timex.SystemClock] (or
// nil — the cache normalises) when the OP is not under test.
func NewFetcher(clock timex.Clock) *Fetcher {
	return &Fetcher{
		cache: newJWKSCache(clock),
	}
}

// SetAllowPrivate toggles the SSRF deny-list. Pass true to permit
// JWKS hosts that resolve to loopback / link-local / RFC 1918
// addresses, which is the posture an embedder needs when the RP runs
// inside the same private network as the OP. Cloud-metadata IPs
// remain rejected unconditionally.
func (f *Fetcher) SetAllowPrivate(b bool) {
	f.allowPrivate = b
}

// SetBaseTransport injects a [http.RoundTripper] the fetcher will use
// instead of [securefetch.NewClient]'s default [http.Transport]. The
// caller's transport is preserved verbatim except that the dial-time
// SSRF gate is rewired onto its DialContext — passing a custom
// transport does not bypass the SSRF protections.
//
// Embedders that need a private CA (an internal CA-issued client
// JWKS endpoint, the OFCS conformance harness against a self-signed
// runner cert) supply a transport with the matching TLSClientConfig.
// Production deployments using publicly-trusted certs should leave
// this nil so the package picks up Go's system trust store.
//
// The setter must be called before the first [Fetch]; once the lazy
// client is constructed the transport is captured and later changes
// are ignored.
func (f *Fetcher) SetBaseTransport(rt http.RoundTripper) {
	f.baseTransport = rt
}

// policy returns the [securefetch.Policy] snapshot the fetcher uses
// to construct its lazy client. The function is the single source of
// truth so the URL-time and dial-time gates always agree on the
// AllowPrivate posture.
func (f *Fetcher) policy() securefetch.Policy {
	return securefetch.Policy{
		AllowPrivateNetwork: f.allowPrivate,
		MaxBodyBytes:        defaultJWKSMaxBody,
		Timeout:             defaultJWKSTimeout,
		BaseTransport:       f.baseTransport,
		AcceptContentTypes:  []string{"application/json", "application/jwk-set+json"},
	}
}

// client returns the lazily-constructed [*securefetch.Client]. The
// lazy initialisation lets [verify.go]'s [AllowPrivateNetwork] option
// mutate [allowPrivate] after construction without rebuilding the
// transport mid-fetch.
func (f *Fetcher) client() *securefetch.Client {
	f.clientOnce.Do(func() {
		f.clientFetch = securefetch.NewClient(f.policy())
	})
	return f.clientFetch
}

// Fetch retrieves the parsed keyset for jwksURI. The cache is consulted
// first; on a miss or expired entry the function performs the HTTP
// round-trip, applies the security checks, and updates the cache.
//
// Concurrent fetches against the same URL collapse onto a single
// outbound request via [singleflight.Group]; this prevents a thundering
// herd against the RP when the cache expires under load and stops a
// hostile client from forcing N parallel JWKS fetches by replaying the
// same JAR N times.
func (f *Fetcher) Fetch(ctx context.Context, jwksURI string) (*josev4.JSONWebKeySet, error) {
	if entry, ok := f.cache.get(jwksURI); ok {
		return entry.keys, nil
	}
	if ok, cached := f.cache.getFailure(jwksURI); ok {
		return nil, cached
	}
	v, err, _ := f.flight.Do(jwksURI, func() (any, error) {
		// Re-check the positive cache inside the singleflight to make
		// sure a concurrent winner that completed between our get
		// above and the call here does not force a redundant fetch.
		if entry, ok := f.cache.get(jwksURI); ok {
			return entry.keys, nil
		}
		keys, err := f.doFetch(ctx, jwksURI)
		if err != nil {
			f.cache.putFailure(jwksURI, err, defaultJWKSNegativeTTL)
			return nil, err
		}
		return keys, nil
	})
	if err != nil {
		return nil, err
	}
	keys, ok := v.(*josev4.JSONWebKeySet)
	if !ok {
		return nil, fmt.Errorf("%w: singleflight returned %T", ErrJWKSFetch, v)
	}
	return keys, nil
}

// doFetch performs the HTTP round-trip and the response post-processing.
// The function is split out from [Fetch] so the singleflight collapses
// only the network path, while the cache lookup and negative-cache
// bookkeeping run on every caller.
//
// The conditional-GET / 304 branch precludes using the canonical
// [securefetch.Client.Get] helper (the helper rejects non-2xx as
// [securefetch.ErrUnexpectedStatus]); the function instead builds the
// request through [securefetch.Client.NewRequest] (which runs the
// URL-time gate) and dispatches it via [securefetch.Client.DoRaw]
// (which goes through the dial-time gate but skips the response
// gates), then re-implements the body cap / status / content-type
// checks inline so the 304 branch can short-circuit before the body
// read.
func (f *Fetcher) doFetch(ctx context.Context, jwksURI string) (*josev4.JSONWebKeySet, error) {
	cached, _ := f.cache.get(jwksURI)
	req, err := f.client().NewRequest(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWKSFetch, err)
	}
	req.Header.Set("Accept", "application/json")
	if cached != nil && cached.etag != "" {
		req.Header.Set("If-None-Match", cached.etag)
	}
	resp, err := f.client().DoRaw(req)
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

// IsLocalHostname reports whether host is a literal "localhost" string
// or one of its common variants. Forwards to [internal/netsec.IsLocalHostname]
// so the deny-list is centralised; retained as a [jar] export because
// existing call sites (authorizeendpoint, sector, backchannel) reach
// the helper through this package.
func IsLocalHostname(host string) bool {
	return netsec.IsLocalHostname(host)
}

// IsPrivateIP reports whether ip falls inside one of the deny-listed
// ranges. Forwards to [internal/netsec.IsPrivateIP]; retained for the
// same reason as [IsLocalHostname].
func IsPrivateIP(ip net.IP) bool {
	return netsec.IsPrivateIP(ip)
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
