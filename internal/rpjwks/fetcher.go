package rpjwks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/remotecache"
	"github.com/libraz/go-oidc-provider/internal/securefetch"
	"github.com/libraz/go-oidc-provider/internal/timex"
)

// The limits every relying-party JWKS fetch is subject to. They live here
// rather than at the call sites so the three OP surfaces that resolve a
// jwks_uri cannot drift apart: a value that is safe for request objects is by
// construction the value the token endpoint and the encryption path use too.
const (
	// DefaultTimeout caps the total time one fetch may take, including connect,
	// TLS, and body read. It is independent of the inbound request's budget, so
	// a slowloris RP cannot stall an OP request thread regardless of whatever
	// timeouts the embedder configured on its own server.
	DefaultTimeout = 5 * time.Second

	// DefaultTTL is the freshness lifetime applied to a fetched keyset when the
	// response advertises no Cache-Control max-age. Short enough that a key
	// rotation propagates without operator intervention, long enough that the
	// common case costs no network round-trip.
	DefaultTTL = 5 * time.Minute

	// DefaultNegativeTTL caps how long a fetch failure is cached against a URL.
	// The negative cache defeats amplification: a peer replaying a request that
	// names an unreachable jwks_uri would otherwise cost one outbound socket per
	// inbound request. A few seconds collapses bursts without delaying recovery
	// from a transient RP outage noticeably.
	DefaultNegativeTTL = remotecache.DefaultNegativeTTL

	// DefaultMaxEntries bounds the cache's URL cardinality. Positive and
	// negative entries share the budget and eviction is least-recently-used, so
	// hostile registrations can neither grow process memory without bound nor
	// choose which client's keyset gets dropped.
	DefaultMaxEntries = remotecache.DefaultMaxEntries

	// DefaultMaxBodyBytes caps the response body at 64 KiB. Real keysets are
	// well under 4 KiB, and MaxKeys bounds the member count independently; the
	// ceiling exists to bound memory against a malicious or misconfigured peer.
	DefaultMaxBodyBytes = int64(64 * 1024)

	// DefaultMaxInflight bounds the number of distinct remote URL loads that
	// may be in flight across all Fetcher instances in this process. The
	// nonblocking gate fails closed when saturated; callers can retry without
	// turning a burst of open-DCR URLs into an unbounded socket/goroutine fanout.
	DefaultMaxInflight = 64

	// MaxKeys bounds how many members a keyset may declare, in addition to the
	// body cap. It is not configurable: no deployment has a reason to publish
	// more, and a per-caller override would be exactly the drift this package
	// exists to remove.
	MaxKeys = 64

	// ForcedRefreshInterval throttles [Fetcher.FetchFresh] per URL. The forced
	// path exists for a legitimate reason — a signature naming a key the cached
	// set does not contain is evidence the RP rotated — but the trigger is
	// attacker-supplied, so without a throttle a peer minting signatures with
	// random key ids turns each one into an outbound request at the RP's host.
	// The interval is per URL and never consults the key id, so N distinct
	// unknown ids inside one window still cost exactly one round-trip, while a
	// genuine rotation still propagates within seconds.
	ForcedRefreshInterval = 20 * time.Second
)

// ErrFetch is the sentinel a [Fetcher] wraps its failures in when the caller
// left [Config.FetchError] unset.
var ErrFetch = errors.New("rpjwks: jwks fetch failed")

// ErrOverloaded identifies a transient refusal caused by the shared
// in-flight URL-load bound. It is intentionally distinct from an upstream
// fetch failure so the cache never negative-caches capacity pressure.
var ErrOverloaded = errors.New("rpjwks: URL-load capacity exhausted")

// TransientError marks a failure that callers should retry rather than treat
// as evidence that the RP's JWKS document is bad. Overload currently uses this
// type; the wrapper leaves room for other transient fetch conditions without
// changing the caller's errors.As contract.
type TransientError struct {
	Cause error
}

func (e *TransientError) Error() string {
	if e == nil || e.Cause == nil {
		return "rpjwks: transient fetch failure"
	}
	return e.Cause.Error()
}

func (e *TransientError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}

// Temporary allows legacy retry loops to recognise the error without
// depending on the concrete type. It is deliberately not used by the cache;
// [Config] installs the more precise errors.Is filter below.
func (*TransientError) Temporary() bool { return true }

// errNoKeySet reports that the cache returned success without a keyset, which
// would be an internal inconsistency rather than an upstream condition.
var errNoKeySet = errors.New("cache returned no keyset")

// Config configures [New]. The zero value is a hardened production posture:
// deny-list engaged, default limits, bounded TTL/LRU cache, short negative
// caching. Every duration and size field falls back to its package default when
// left zero; a negative value never disables the bound.
type Config struct {
	// FetchError is the sentinel every failure this fetcher returns wraps, so a
	// calling package keeps its own errors.Is contract while sharing one
	// implementation. Nil falls back to [ErrFetch].
	FetchError error

	// Clock drives the cache TTLs and the forced-refresh throttle. Nil falls
	// back to [timex.SystemClock]; tests inject a fake clock so cache behaviour
	// is deterministic without sleeping.
	Clock timex.Clock

	// Timeout caps one outbound fetch. Zero falls back to [DefaultTimeout].
	Timeout time.Duration

	// TTL is the cache lifetime for a keyset whose response advertised no
	// Cache-Control max-age. Zero falls back to [DefaultTTL].
	TTL time.Duration

	// NegativeTTL is the lifetime of a cached fetch failure. Zero falls back to
	// [DefaultNegativeTTL].
	NegativeTTL time.Duration

	// MaxEntries bounds the combined positive/negative URL cardinality. Zero
	// falls back to [DefaultMaxEntries].
	MaxEntries int

	// MaxBodyBytes caps the response body. Zero falls back to
	// [DefaultMaxBodyBytes].
	MaxBodyBytes int64

	// MaxInflight bounds this fetcher's contribution to the process-wide
	// nonblocking URL-load gate. Zero or a negative value uses
	// [DefaultMaxInflight]. The shared gate always applies, so increasing this
	// value cannot raise the process-wide default; values above the default are
	// clamped, while a smaller value is useful for an individual caller that
	// needs a tighter budget.
	MaxInflight int

	// AllowPrivateNetwork lifts the SSRF deny-list so a deployment that
	// legitimately hosts its RPs on a private LAN can reach them. Cloud-metadata
	// addresses remain rejected even with this set.
	AllowPrivateNetwork bool

	// BaseTransport overrides the [http.RoundTripper] the SSRF-hardened client
	// is built on. Production callers leave it nil; a caller that needs a
	// private CA (an internal CA-issued RP endpoint, a conformance harness with
	// a self-signed cert) or an already-instrumented transport injects one here.
	// The dial-time SSRF hook is reinstalled on the supplied transport, so a
	// custom transport does not widen the surface.
	BaseTransport http.RoundTripper
}

// entry is the cached projection of one keyset: the parsed keys plus the ETag
// the upstream advertised, so an expired entry can be revalidated with a
// conditional GET instead of a full re-download.
type entry struct {
	keys *josev4.JSONWebKeySet
	etag string
}

// Fetcher resolves a relying party's jwks_uri into parsed keys, with caching,
// singleflight collapsing, the SSRF envelope, and the package limits applied.
// It is safe for concurrent use; callers construct one at startup and share it
// across every path that resolves the same population of clients.
type Fetcher struct {
	cache  *remotecache.Cache[*entry]
	forced *remotecache.Cache[struct{}]
	// forcedMu makes the throttle's check-and-record atomic, so a burst of
	// concurrent forced refreshes cannot each observe an empty slot.
	forcedMu sync.Mutex

	fetchErr error
	timeout  time.Duration
	maxBody  int64
	inflight chan struct{}

	// clientOnce / client wire the lazy [*securefetch.Client] construction so a
	// caller can flip the posture setters after [New] returned but before the
	// first fetch without re-allocating the client on every fetch.
	clientOnce sync.Once
	client     *securefetch.Client

	allowPrivate  bool
	baseTransport http.RoundTripper
}

// globalURLLoadSlots is the process-wide hard ceiling. The per-policy groups
// below provide tighter local budgets while this channel keeps independently
// configured components from exceeding the safe process default in aggregate.
//
//nolint:gochecknoglobals // one process-wide capacity gate is the contract.
var (
	globalURLLoadSlots        = make(chan struct{}, DefaultMaxInflight)
	globalURLLoadSlotsMu      sync.Mutex
	globalURLLoadSlotsByLimit = map[int]chan struct{}{
		DefaultMaxInflight: make(chan struct{}, DefaultMaxInflight),
	}
)

func sharedURLLoadSlots(limit int) chan struct{} {
	globalURLLoadSlotsMu.Lock()
	defer globalURLLoadSlotsMu.Unlock()
	if slots := globalURLLoadSlotsByLimit[limit]; slots != nil {
		return slots
	}
	slots := make(chan struct{}, limit)
	globalURLLoadSlotsByLimit[limit] = slots
	return slots
}

// New returns a fetcher with the [Config] defaults applied.
func New(cfg Config) *Fetcher {
	if cfg.FetchError == nil {
		cfg.FetchError = ErrFetch
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.NegativeTTL <= 0 {
		cfg.NegativeTTL = DefaultNegativeTTL
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = DefaultMaxEntries
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = DefaultMaxBodyBytes
	}
	if cfg.MaxInflight <= 0 {
		cfg.MaxInflight = DefaultMaxInflight
	} else if cfg.MaxInflight > DefaultMaxInflight {
		// Keep the per-policy channel bounded too. The process-wide hard
		// gate already prevents extra network loads, but accepting an
		// arbitrarily large caller value here would allocate an avoidable
		// attacker-sized channel during construction.
		cfg.MaxInflight = DefaultMaxInflight
	}
	return &Fetcher{
		cache: remotecache.New[*entry](remotecache.Config{
			Clock:       cfg.Clock,
			TTL:         cfg.TTL,
			NegativeTTL: cfg.NegativeTTL,
			MaxEntries:  cfg.MaxEntries,
			ShouldCacheError: func(err error) bool {
				// Capacity pressure is a local transient, not an upstream
				// document failure. Never let one saturated request suppress
				// later callers during the negative-cache window.
				return !errors.Is(err, ErrOverloaded)
			},
		}),
		forced: remotecache.New[struct{}](remotecache.Config{
			Clock:      cfg.Clock,
			TTL:        ForcedRefreshInterval,
			MaxEntries: cfg.MaxEntries,
		}),
		fetchErr:      cfg.FetchError,
		timeout:       cfg.Timeout,
		maxBody:       cfg.MaxBodyBytes,
		inflight:      sharedURLLoadSlots(cfg.MaxInflight),
		allowPrivate:  cfg.AllowPrivateNetwork,
		baseTransport: cfg.BaseTransport,
	}
}

// SetAllowPrivate toggles the SSRF deny-list after construction. Pass true to
// permit JWKS hosts that resolve to loopback / link-local / RFC 1918 addresses,
// which is the posture an embedder needs when its RPs run inside the same
// private network as the OP. Cloud-metadata addresses remain rejected.
//
// The setter must run before the first fetch; once the lazy client is built the
// posture is captured and later changes are ignored.
func (f *Fetcher) SetAllowPrivate(b bool) {
	f.allowPrivate = b
}

// SetBaseTransport injects the [http.RoundTripper] described by
// [Config.BaseTransport] after construction. The same "before the first fetch"
// rule as [Fetcher.SetAllowPrivate] applies.
func (f *Fetcher) SetBaseTransport(rt http.RoundTripper) {
	f.baseTransport = rt
}

// CacheLen reports how many positive and negative entries the cache retains
// after pruning expired ones.
func (f *Fetcher) CacheLen() int {
	return f.cache.Len()
}

// Fetch returns the parsed keyset for jwksURI. A fresh cached entry answers
// without a round-trip; an expired one is revalidated conditionally when the
// upstream gave an ETag. Concurrent fetches for one URL collapse onto a single
// outbound request, so a peer replaying the same request cannot multiply
// outbound sockets, and a cached failure short-circuits for the negative TTL.
func (f *Fetcher) Fetch(ctx context.Context, jwksURI string) (*josev4.JSONWebKeySet, error) {
	return f.result(f.cache.LoadTTL(ctx, jwksURI, f.load(jwksURI)))
}

// FetchFresh forces a cache-bypassing refetch of jwksURI, for a caller holding
// a cached keyset that does not contain the key a signature names — the signal
// that the RP rotated. Unlike [Fetcher.Fetch] it does not short-circuit on a
// still-fresh entry; it goes to the network (conditionally, so an unchanged
// upstream still costs only a 304) and stores the result.
//
// Forced refetches are throttled per URL by [ForcedRefreshInterval]. When the
// throttle denies one, the cached keyset is returned unchanged and the caller's
// re-verification fails cleanly without a round-trip. Nothing cached means
// there is no entry to protect, so the throttle does not apply and the fetch
// proceeds.
func (f *Fetcher) FetchFresh(ctx context.Context, jwksURI string) (*josev4.JSONWebKeySet, error) {
	// The probe is non-destructive so an expired entry keeps its ETag, letting
	// the refresh below revalidate conditionally instead of re-downloading.
	if cached, ok := f.cache.PeekFresh(jwksURI); ok && cached != nil && !f.tryForced(jwksURI) {
		return cached.keys, nil
	}
	keys, err := f.cache.RefreshTTL(ctx, jwksURI, f.load(jwksURI))
	if errors.Is(err, ErrOverloaded) {
		// A forced refresh marker is an admission throttle, not a record of
		// successful work. Capacity pressure leaves the positive cache intact
		// and must release the marker so the next caller can retry immediately
		// once a URL-load slot is available.
		f.clearForced(jwksURI)
	}
	return f.result(keys, err)
}

// ParseKeySet decodes an inline keyset under this fetcher's error taxonomy, so
// a caller resolving both inline JWKs and a jwks_uri applies one member cap and
// one tolerance rule to both.
func (f *Fetcher) ParseKeySet(body []byte) (*josev4.JSONWebKeySet, error) {
	keys, err := parseKeySet(body, MaxKeys)
	if err != nil {
		return nil, f.wrap(err)
	}
	return keys, nil
}

// tryForced reports whether a forced refetch is permitted for url right now,
// recording the attempt when it returns true. It returns false while a previous
// forced refetch sits inside [ForcedRefreshInterval], so a burst of signatures
// bearing unknown key ids collapses to at most one outbound fetch per interval
// per URL.
func (f *Fetcher) tryForced(url string) bool {
	f.forcedMu.Lock()
	defer f.forcedMu.Unlock()
	if _, ok, _ := f.forced.Get(url); ok {
		return false
	}
	f.forced.Put(url, struct{}{})
	return true
}

func (f *Fetcher) clearForced(url string) {
	f.forcedMu.Lock()
	f.forced.Delete(url)
	f.forcedMu.Unlock()
}

// load returns the cache loader for jwksURI.
//
// The round-trip runs under a context detached from the caller's request. A
// singleflight winner's context is shared by every collapsed waiter, so leaving
// the fetch bound to it would let one caller — an unauthenticated peer driving
// an endpoint that resolves this client, say — abort the fetch every other
// waiter depends on. The detached context keeps the caller's values (log and
// trace correlation) but carries the fetcher's own deadline.
func (f *Fetcher) load(jwksURI string) remotecache.TTLLoader[*entry] {
	return func(ctx context.Context, stale *entry, hasStale bool) (*entry, time.Duration, error) {
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), f.timeout)
		defer cancel()
		if !hasStale {
			stale = nil
		}
		return f.doFetch(fetchCtx, jwksURI, stale)
	}
}

// doFetch performs the HTTP round-trip and the response post-processing.
//
// The conditional-GET branch precludes the canonical [securefetch.Client.Get]
// helper, which rejects a 304 as an unexpected status. The request is built
// through [securefetch.Client.NewRequest] (which runs the URL-time gate) and
// dispatched via [securefetch.Client.DoRaw] (which goes through the dial-time
// gate but skips the response gates), and the status / content-type / body-cap
// checks are applied here so the 304 branch can short-circuit before the body
// read.
func (f *Fetcher) doFetch(ctx context.Context, jwksURI string, cached *entry) (*entry, time.Duration, error) {
	release, err := f.acquireLoad(ctx)
	if err != nil {
		return nil, 0, err
	}
	defer release()

	req, err := f.secureClient().NewRequest(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", "application/json")
	if cached != nil && cached.etag != "" {
		req.Header.Set("If-None-Match", cached.etag)
	}
	resp, err := f.secureClient().DoRaw(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	if cached != nil && resp.StatusCode == http.StatusNotModified {
		// The cached keyset is still authoritative; renew its freshness
		// without re-parsing.
		return cached, ttlFromResponse(resp), nil
	}
	if resp.StatusCode/100 != 2 {
		return nil, 0, fmt.Errorf("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !isJSONContentType(ct) {
		return nil, 0, fmt.Errorf("content-type %q is not JSON", ct)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBody+1))
	if err != nil {
		return nil, 0, fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > f.maxBody {
		return nil, 0, fmt.Errorf("body exceeds %d bytes", f.maxBody)
	}
	keys, err := parseKeySet(body, MaxKeys)
	if err != nil {
		return nil, 0, err
	}
	return &entry{keys: keys, etag: resp.Header.Get("ETag")}, ttlFromResponse(resp), nil
}

// acquireLoad takes both the process-wide hard ceiling and this fetcher's
// tighter policy group. The operation is deliberately nonblocking: a
// saturated attacker-controlled URL population receives a typed transient
// error rather than queuing goroutines behind a semaphore. The release closure
// always returns both slots, including every request/parse error path.
func (f *Fetcher) acquireLoad(ctx context.Context) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	select {
	case globalURLLoadSlots <- struct{}{}:
	default:
		return nil, &TransientError{Cause: ErrOverloaded}
	}
	select {
	case f.inflight <- struct{}{}:
		return func() {
			<-f.inflight
			<-globalURLLoadSlots
		}, nil
	default:
		<-globalURLLoadSlots
		return nil, &TransientError{Cause: ErrOverloaded}
	}
}

// result maps a cache outcome onto the caller's keyset / sentinel contract.
func (f *Fetcher) result(e *entry, err error) (*josev4.JSONWebKeySet, error) {
	if err != nil {
		return nil, f.wrap(err)
	}
	if e == nil {
		return nil, f.wrap(errNoKeySet)
	}
	return e.keys, nil
}

// wrap attaches the caller's sentinel to err. An error that already carries the
// sentinel — a negative-cache hit replayed to a second caller — passes through
// unchanged rather than accumulating a prefix per replay.
func (f *Fetcher) wrap(err error) error {
	if errors.Is(err, f.fetchErr) {
		return err
	}
	return fmt.Errorf("%w: %w", f.fetchErr, err)
}

// secureClient returns the lazily-constructed SSRF-hardened client. The lazy
// construction is what lets [Fetcher.SetAllowPrivate] and
// [Fetcher.SetBaseTransport] run after [New] without rebuilding the transport
// mid-fetch.
func (f *Fetcher) secureClient() *securefetch.Client {
	f.clientOnce.Do(func() {
		f.client = securefetch.NewClient(securefetch.Policy{
			AllowPrivateNetwork: f.allowPrivate,
			MaxBodyBytes:        f.maxBody,
			Timeout:             f.timeout,
			BaseTransport:       f.baseTransport,
			AcceptContentTypes:  []string{"application/json", "application/jwk-set+json"},
		})
	})
	return f.client
}
