package sector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/internal/netsec"
	"github.com/libraz/go-oidc-provider/internal/securefetch"
	"github.com/libraz/go-oidc-provider/internal/timex"
)

// Default knobs for the sector_identifier_uri fetcher. The values
// match the OIDC Core 1.0 §5 informative posture (small JSON document,
// no streaming) and the in-tree SSRF defenses applied to the JAR /
// JWKS fetchers; embedders that need different shapes wire explicit
// overrides through [Option].
const (
	// defaultTimeout caps the total time spent fetching a sector
	// document, including connect, TLS, and body read. Five seconds
	// matches the JAR / JWKS fetcher budget so the three SSRF gates
	// share a single operator expectation.
	defaultTimeout = 5 * time.Second

	// defaultMaxBody caps the body size at 64 KiB. A real
	// sector_identifier document lists a handful of redirect URIs,
	// so 64 KiB is two orders of magnitude over the realistic upper
	// bound while bounding memory use against a malicious peer.
	defaultMaxBody = int64(64 * 1024)

	// jsonContentType is the only Content-Type the resolver accepts.
	// Sector documents are pure JSON arrays per OIDC Core 1.0 §5;
	// peers that emit application/octet-stream or text/html are
	// almost always misconfigured (CDN error pages, captive portal).
	jsonContentType = "application/json"
)

// Sentinel errors. Each error wraps [ErrSectorFetch] so callers can
// distinguish the family with [errors.Is] while still inspecting the
// specific cause via [errors.As].
var (
	// ErrSectorFetch is the family root the resolver returns from
	// every failure path. Callers that only care "did the fetch
	// succeed" check errors.Is(err, ErrSectorFetch).
	ErrSectorFetch = errors.New("sector: fetch failed")

	// ErrSectorPrivateAddress signals the URL or its DNS resolution
	// pointed at a deny-listed host (loopback / link-local / RFC 1918
	// / IPv6 ULA). Embedders fronting RPs through private DNS opt
	// out via [Option.AllowPrivateNetwork].
	ErrSectorPrivateAddress = errors.New("sector: host resolves to a private address")

	// ErrSectorRedirectFollowed signals an upstream that responded
	// with a 3xx. The resolver refuses redirects so an attacker who
	// controls a public DNS entry cannot use it to pivot onto a
	// private destination.
	ErrSectorRedirectFollowed = errors.New("sector: refused to follow redirect")

	// ErrSectorContentChanged signals the cache held an entry whose
	// SHA-256 hash differs from the freshly fetched document. The
	// surface lets operators distinguish a deliberate RP rotation
	// from a sector hijack; the resolver does not auto-promote the
	// new content.
	ErrSectorContentChanged = errors.New("sector: document hash differs from cached value")

	// ErrSectorRedirectMissing signals one or more of the client's
	// registered redirect_uris were absent from the sector document
	// per OIDC Core 1.0 §5.
	ErrSectorRedirectMissing = errors.New("sector: client redirect_uri not listed in sector document")

	// ErrSectorMalformed signals the body was not a JSON array of
	// strings.
	ErrSectorMalformed = errors.New("sector: document is not a JSON array of strings")
)

// Option configures a [Resolver]. Options compose: the order in which
// they appear in the [New] call determines apply order; later options
// override earlier ones for the same field.
type Option func(*resolverConfig)

type resolverConfig struct {
	clock              timex.Clock
	httpClient         *http.Client
	timeout            time.Duration
	maxBody            int64
	ttl                time.Duration
	allowPrivate       bool
	resolverLookupHook func(ctx context.Context, host string) ([]net.IPAddr, error)
}

// WithClock injects the wall clock the cache TTL is measured against.
// A nil clock leaves the resolver on [timex.SystemClock]; tests pass
// a fake clock to exercise expiry deterministically.
func WithClock(c timex.Clock) Option {
	return func(cfg *resolverConfig) { cfg.clock = c }
}

// WithHTTPClient overrides the [*http.Client] the resolver uses. The
// supplied client's transport is left untouched, but the resolver
// installs its own CheckRedirect hook so an embedder-supplied client
// cannot accidentally re-enable redirect following.
//
// The default client is constructed lazily with the timeout and
// CheckRedirect posture documented on the package; embedders only
// need this option for tests that swap in an httptest.Server transport.
func WithHTTPClient(c *http.Client) Option {
	return func(cfg *resolverConfig) { cfg.httpClient = c }
}

// WithTimeout overrides the per-fetch budget. Zero or negative leaves
// the default [defaultTimeout] in place.
func WithTimeout(d time.Duration) Option {
	return func(cfg *resolverConfig) {
		if d > 0 {
			cfg.timeout = d
		}
	}
}

// WithMaxBody overrides the body cap. Zero or negative leaves the
// default [defaultMaxBody] in place. Embedders SHOULD NOT raise the
// cap above 1 MiB without an explicit threat-model justification — a
// large sector document is almost always a misconfiguration.
func WithMaxBody(n int64) Option {
	return func(cfg *resolverConfig) {
		if n > 0 {
			cfg.maxBody = n
		}
	}
}

// WithTTL overrides the cache TTL. Zero or negative leaves the
// default [timex.SectorURICacheTTLDefault] in place.
func WithTTL(d time.Duration) Option {
	return func(cfg *resolverConfig) {
		if d > 0 {
			cfg.ttl = d
		}
	}
}

// AllowPrivateNetwork lifts the SSRF deny-list. Embedders fronting
// their RPs through private DNS use the option to keep the same
// fetcher across deployments; the matching production path leaves
// the gate engaged so an attacker-controlled sector_identifier_uri
// cannot pivot onto an internal service.
func AllowPrivateNetwork() Option {
	return func(cfg *resolverConfig) { cfg.allowPrivate = true }
}

// withResolverLookupHook injects a custom DNS resolution function.
// Unexported because production callers always go through
// [net.DefaultResolver]; the hook exists so tests can simulate
// "public hostname that resolves to a private address" without
// wiring a real DNS server.
func withResolverLookupHook(fn func(ctx context.Context, host string) ([]net.IPAddr, error)) Option {
	return func(cfg *resolverConfig) { cfg.resolverLookupHook = fn }
}

// Resolver fetches and validates sector_identifier_uri documents. The
// type is safe for concurrent use; cache reads and writes serialise
// through an internal RWMutex.
type Resolver struct {
	cfg    resolverConfig
	cache  *cache
	client *securefetch.Client
}

// New returns a [Resolver] configured by the supplied options. The
// returned value is ready for concurrent use; embedders typically
// share a single Resolver across all goroutines that touch the
// dynamic-registration endpoint.
func New(opts ...Option) *Resolver {
	cfg := resolverConfig{
		clock:   timex.SystemClock,
		timeout: defaultTimeout,
		maxBody: defaultMaxBody,
		ttl:     timex.SectorURICacheTTLDefault,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.clock == nil {
		cfg.clock = timex.SystemClock
	}
	policy := securefetch.Policy{
		AllowPrivateNetwork: cfg.allowPrivate,
		AllowedSchemes:      []string{"https"},
		MaxBodyBytes:        cfg.maxBody,
		AcceptContentTypes:  []string{jsonContentType},
		Timeout:             cfg.timeout,
		LookupHook:          cfg.resolverLookupHook,
		CheckRedirect:       refuseRedirect,
	}
	if cfg.httpClient != nil {
		policy = policy.WithHTTPClientForTest(cfg.httpClient)
	}
	return &Resolver{
		cfg:    cfg,
		cache:  newCache(cfg.clock),
		client: securefetch.NewClient(policy),
	}
}

// Resolve fetches sector_identifier_uri (or returns the cached entry
// when fresh), confirms every entry in registeredRedirectURIs appears
// in the upstream document, and returns the canonical sector host
// (the lower-cased URL host, used as the per-RP scope of the
// pairwise hash).
//
// The function is the only public entry point because every
// validation rule the dynamic registration endpoint applies — SSRF
// gate, body cap, content-type, JSON shape, redirect_uri subset,
// hash stability — composes here. Splitting "fetch" from "verify"
// in the public surface would let a future caller skip the subset
// check and admit a sector the RP does not control.
//
// Returned errors wrap [ErrSectorFetch]; specific failure modes are
// reachable via [errors.Is] against the package sentinels.
func (r *Resolver) Resolve(ctx context.Context, sectorIdentifierURI string, registeredRedirectURIs []string) (string, error) {
	host, err := r.assertSafeURL(ctx, sectorIdentifierURI)
	if err != nil {
		return "", err
	}
	registered := canonicaliseURIs(registeredRedirectURIs)
	if entry, ok := r.cache.get(sectorIdentifierURI); ok {
		if err := verifySubset(entry.uris, registered); err != nil {
			return "", err
		}
		return host, nil
	}
	uris, hash, err := r.doFetch(ctx, sectorIdentifierURI)
	if err != nil {
		return "", err
	}
	if existing, ok := r.cache.peek(sectorIdentifierURI); ok && existing.hash != hash {
		// Evict the stale entry before surfacing the mismatch: leaving
		// it in place would compare every future Resolve call against
		// the same now-obsolete hash, permanently poisoning DCR for
		// every client sharing this sector_identifier_uri until the
		// process restarts. The caller still observes
		// ErrSectorContentChanged once as the change-detection signal,
		// but the eviction means the very next Resolve call for this
		// URI sees a clean cache miss and repopulates with the new
		// document's hash, so a legitimate RP-side rotation recovers
		// without operator intervention.
		r.cache.evict(sectorIdentifierURI)
		return "", fmt.Errorf("%w: %w", ErrSectorFetch, ErrSectorContentChanged)
	}
	if err := verifySubset(uris, registered); err != nil {
		return "", err
	}
	r.cache.put(sectorIdentifierURI, &cacheEntry{
		uris:   uris,
		hash:   hash,
		expiry: r.cfg.clock.Now().Add(r.cfg.ttl),
	})
	return host, nil
}

// doFetch performs the HTTP round trip and JSON parse. The function
// is unexported because Resolve's bookkeeping (cache lookup, subset
// check, hash compare) only makes sense as a unit; exposing the raw
// fetch would let a future caller skip the cache-poisoning gate.
//
// Status, Content-Type, body cap, and SSRF gates are applied by the
// shared [*securefetch.Client]; this function only adds the JSON
// parse and the canonicalisation / hashing of the resulting URI list.
func (r *Resolver) doFetch(ctx context.Context, sectorIdentifierURI string) ([]string, string, error) {
	req, err := r.client.NewRequest(ctx, http.MethodGet, sectorIdentifierURI, nil)
	if err != nil {
		return nil, "", classifyFetchError(err)
	}
	req.Header.Set("Accept", jsonContentType)
	body, _, err := r.client.Do(req) //nolint:bodyclose // securefetch.Do drains and closes the body internally.
	if err != nil {
		return nil, "", classifyFetchError(err)
	}
	uris, err := parseSectorDocument(body)
	if err != nil {
		return nil, "", err
	}
	return canonicaliseURIs(uris), hashURIs(uris), nil
}

// assertSafeURL is the SSRF gate. It runs before any network I/O so
// an attacker-controlled sector_identifier_uri cannot exhaust DNS or
// TCP resources just to be rejected on the response. The function
// returns the canonical sector host (lower-cased) on success so the
// caller does not have to re-parse the URL.
//
// The actual deny-list lives in [internal/netsec.AssertSafeURL]; this
// wrapper translates the package-level error into the sector
// taxonomy ([ErrSectorPrivateAddress] / [ErrSectorFetch]) so callers
// can branch with [errors.Is] against the existing sentinels.
//
// The dial-time check installed by [internal/netsec.NewHTTPClient] re-runs the
// same deny-list against the kernel-resolved address, so a TOCTOU
// rebinding between this gate and [http.Client.Do] cannot escape.
// Cloud-metadata IPs (169.254.169.254 et al) remain rejected even
// when [Option.AllowPrivateNetwork] is set.
func (r *Resolver) assertSafeURL(ctx context.Context, raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%w: parse url: %w", ErrSectorFetch, err)
	}
	host := u.Hostname()
	if err := r.client.AssertSafeURLParsed(ctx, u); err != nil {
		return "", classifyNetsecError(err)
	}
	return strings.ToLower(host), nil
}

// classifyNetsecError maps a [netsec] sentinel onto the sector-package
// taxonomy. Loopback / RFC 1918 / cloud-metadata rejections collapse
// onto [ErrSectorPrivateAddress] so callers can keep their existing
// [errors.Is] branch; everything else flows through [ErrSectorFetch]
// so the family root still matches.
func classifyNetsecError(err error) error {
	switch {
	case errors.Is(err, netsec.ErrPrivateNetworkBlocked),
		errors.Is(err, netsec.ErrCloudMetadataBlocked):
		return fmt.Errorf("%w: %w (%w)", ErrSectorFetch, ErrSectorPrivateAddress, err)
	default:
		return fmt.Errorf("%w: %w", ErrSectorFetch, err)
	}
}

// classifyFetchError maps an error returned from the
// [*securefetch.Client] (transport failure, status / content-type
// rejection, refused redirect) onto the sector taxonomy. The mapping
// preserves the historical errors.Is matrix the resolver tests pin:
// a refused redirect surfaces as [ErrSectorRedirectFollowed]; an
// SSRF rejection flowing through the gate at request-build time
// reuses [classifyNetsecError]; everything else falls through to
// [ErrSectorFetch].
func classifyFetchError(err error) error {
	if errors.Is(err, ErrSectorRedirectFollowed) {
		return err
	}
	if errors.Is(err, netsec.ErrPrivateNetworkBlocked) ||
		errors.Is(err, netsec.ErrCloudMetadataBlocked) ||
		errors.Is(err, netsec.ErrSchemeNotAllowed) ||
		errors.Is(err, netsec.ErrMissingHost) {
		return classifyNetsecError(err)
	}
	return fmt.Errorf("%w: %w", ErrSectorFetch, err)
}

// refuseRedirect is the [http.Client.CheckRedirect] hook installed on
// every fetcher. The OIDC Core 1.0 §5 sector document is fetched
// against a public, RP-controlled URL; an upstream redirect almost
// always signals one of two failure modes — a misconfigured CDN, or
// an attempt to pivot the OP onto a different host whose SSRF
// disposition was not validated. Both are refused.
func refuseRedirect(*http.Request, []*http.Request) error {
	return fmt.Errorf("%w: %w", ErrSectorFetch, ErrSectorRedirectFollowed)
}

// parseSectorDocument decodes body into the OIDC Core 1.0 §5 array
// shape. Empty arrays are accepted at this layer — they are
// syntactically valid; the redirect-subset check at the call site
// catches the semantic problem.
func parseSectorDocument(body []byte) ([]string, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("%w: %w (empty body)", ErrSectorFetch, ErrSectorMalformed)
	}
	var uris []string
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields() // catches object-shaped bodies at the top level.
	if err := dec.Decode(&uris); err != nil {
		return nil, fmt.Errorf("%w: %w (%w)", ErrSectorFetch, ErrSectorMalformed, err)
	}
	// A pure JSON array document has nothing left in the stream after
	// the top-level array closes. dec.More reports true when trailing
	// bytes follow (e.g. a second JSON value, or non-JSON garbage
	// appended after the array); OIDC Core 1.0 §5 defines the sector
	// document as exactly one JSON array, so trailing data makes the
	// document malformed even though the array itself decoded cleanly.
	if dec.More() {
		return nil, fmt.Errorf("%w: %w (trailing data after JSON array)", ErrSectorFetch, ErrSectorMalformed)
	}
	return uris, nil
}

// canonicaliseURIs returns a sorted, lower-case-host copy of uris so
// hash and subset comparisons are independent of source ordering or
// case. The function is conservative: it leaves path / query / scheme
// alone so a strict "must match exactly" rule downstream still
// catches typos in the path component.
func canonicaliseURIs(uris []string) []string {
	if len(uris) == 0 {
		return nil
	}
	out := make([]string, 0, len(uris))
	for _, raw := range uris {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			out = append(out, raw)
			continue
		}
		u.Host = strings.ToLower(u.Host)
		out = append(out, u.String())
	}
	sort.Strings(out)
	return out
}

// hashURIs returns the SHA-256 hex of the canonicalised URI list. The
// hex form keeps the value safe to log without disclosing the cache
// key, and lets a debugger compare two stored hashes by eye.
func hashURIs(uris []string) string {
	canon := canonicaliseURIs(uris)
	h := sha256.New()
	for _, raw := range canon {
		_, _ = h.Write([]byte(raw))
		_, _ = h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// verifySubset confirms every entry in registered appears in
// upstream. The comparison is exact-string after canonicalisation;
// case differences in the host are absorbed by canonicaliseURIs but
// path differences ("/cb" vs "/cb/") are intentionally distinct
// because OAuth 2.0 redirect_uri matching is byte-exact.
func verifySubset(upstream, registered []string) error {
	if len(registered) == 0 {
		// A registration with no redirect URIs has nothing to
		// validate against the sector document; the OIDC Core
		// invariant ("every registered redirect appears upstream")
		// holds vacuously.
		return nil
	}
	index := make(map[string]struct{}, len(upstream))
	for _, u := range upstream {
		index[u] = struct{}{}
	}
	for _, want := range registered {
		if _, ok := index[want]; !ok {
			return fmt.Errorf("%w: %w (%q)", ErrSectorFetch, ErrSectorRedirectMissing, want)
		}
	}
	return nil
}

// cache is a tiny thread-safe TTL cache keyed by sector_identifier_uri.
// The implementation mirrors internal/jar/jwks_cache.go; we do not
// share the type because the entry shape (URI list + hash) is
// different and pulling the JWKS-specific etag plumbing into a
// generic abstraction would obscure both subsystems.
type cache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	clock   timex.Clock
}

type cacheEntry struct {
	uris   []string
	hash   string
	expiry time.Time
}

func newCache(clock timex.Clock) *cache {
	if clock == nil {
		clock = timex.SystemClock
	}
	return &cache{entries: make(map[string]*cacheEntry), clock: clock}
}

// get returns the cached entry for uri if it is still within its TTL
// AND the caller may use it without a network round-trip.
func (c *cache) get(uri string) (*cacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[uri]
	if !ok {
		return nil, false
	}
	if c.clock.Now().Before(e.expiry) {
		return e, true
	}
	return nil, false
}

// peek returns any stored entry for uri regardless of expiry. The
// function exists so the cache-poisoning check can compare hashes
// across the boundary where the entry has just expired but the
// previous payload is still authoritative for the change-detection
// rule.
func (c *cache) peek(uri string) (*cacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[uri]
	return e, ok
}

func (c *cache) put(uri string, entry *cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[uri] = entry
}

// evict removes any stored entry for uri. It is called after a
// content-hash mismatch is detected so a legitimate document rotation
// at the RP does not permanently poison future resolutions of the same
// sector_identifier_uri (see the call site in [Resolver.Resolve]).
// Evicting an absent key is a no-op.
func (c *cache) evict(uri string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, uri)
}
