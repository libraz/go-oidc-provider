// Package securefetch hosts the hardened HTTP client envelope every
// outbound RP-controlled fetcher in the OP shares. The package layers
// on top of [internal/netsec]: netsec owns the SSRF deny-list and the
// dial-time gate; this package adds the response-side controls every
// call site re-implemented before consolidation — body cap, accepted
// content-type list, status check, redirect refusal — and packages
// the whole envelope behind a single [*Client].
//
// # Why a shared envelope
//
// The OP reaches RP-controlled URLs from several independent paths
// (JAR JWKS, encryption JWKS, sector_identifier_uri, back-channel
// logout). Each call site previously built its own fetch helper that
// repeated the same six steps:
//
//  1. URL-time SSRF gate via [netsec.AssertSafeURL].
//  2. Dial-time SSRF gate via [netsec.NewHTTPClient].
//  3. Status check (2xx required).
//  4. Optional content-type allow-list.
//  5. Body cap via [io.LimitReader].
//  6. Per-request timeout.
//
// Drift between any two of those reimplementations was the single
// largest source of regressions in prior security reviews; the shared
// envelope makes the security posture a single audit target.
//
// # Per-site differences
//
// The four call sites use different bodies, methods, and response
// shapes. The envelope captures the security-relevant invariants in
// [Policy] and exposes [Client.Get] and [Client.Post] as the request
// constructors; per-site logic (caching, ETag revalidation,
// singleflight collapsing, hash-based change detection) stays at the
// call site so the consolidation does not obscure the protocol-level
// behaviour each fetcher implements.
//
// # Cache and singleflight
//
// The package intentionally does NOT host a shared cache. The four
// fetchers cache different shapes (parsed JWKS, URI lists with hashes,
// nothing at all) with different TTLs and different invalidation
// strategies; pulling the cache plumbing into a shared abstraction
// would either lose information (the JAR ETag plumbing has no analogue
// in the sector cache) or grow a multi-headed interface that obscures
// each call site's intent. Protocol-specific cache policy stays in each
// fetcher; sector and client-encryption JWKS share only the bounded TTL/LRU,
// singleflight, and negative-cache mechanics through `internal/remotecache`.
package securefetch
