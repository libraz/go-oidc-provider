// Package sector resolves and validates OpenID Connect Core 1.0 §5
// sector_identifier_uri references for the pairwise subject strategy
// (op.WithPairwiseSubject / op/subject.Pairwise).
//
// # Two-stage role
//
// Pairwise subject derivation needs only the host of
// sector_identifier_uri at runtime; that is a pure URL parse and
// lives in the op/subject sub-package. The fetch this package
// implements happens at a different stage: dynamic client
// registration (RFC 7591 §2 / OpenID Connect Discovery 1.0 §5)
// requires the OP to confirm the RP actually controls the named
// sector before subjects are minted under it. The Resolver fetches
// the document, verifies it is a JSON array of strings, and reports
// whether every redirect URI the client registered appears in the
// array. A success is cached for 24 hours; failures are not cached
// indefinitely. Fetch and parse failures use a five-second negative cache so a
// burst cannot amplify into one outbound request per registration, then retry
// automatically after that short window.
//
// Positive and negative entries share a 256-URL LRU budget. Expired entries
// are physically removed, and concurrent fetches for one URL collapse onto a
// single outbound request.
//
// # SSRF posture
//
// The fetcher consolidates its SSRF gate in internal/netsec: the
// deny-list (loopback / link-local / RFC 1918 / IPv6 ULA / cloud
// metadata) and the hardened [*http.Client] (re-checking the
// kernel-resolved address at dial time to defeat DNS rebinding) are
// shared with the JAR JWKS fetcher and the back-channel logout
// deliverer. The package adds https-only scheme pinning, no
// redirects, a 64 KiB body cap, and a 5 s request timeout on top of
// that base. Embedders fronting their RPs behind private DNS opt in
// via [AllowPrivateNetwork]; cloud-metadata IPs remain
// rejected even when the opt-in is set.
//
// # Cache poisoning protection
//
// Each cache hit records a SHA-256 hash of the canonicalised redirect
// URI list; a peer that flips the list after the cache populates
// fails the subsequent refresh with [ErrSectorContentChanged] rather
// than silently widening or narrowing the trusted set. Operators
// observe the failure as a configuration_error from the dynamic
// registration endpoint and can decide whether to re-register the
// client or refuse the change.
package sector
