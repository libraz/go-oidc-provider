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
// so a transient outage does not block a re-attempted registration.
//
// # SSRF posture
//
// The fetcher matches the in-tree posture established by
// internal/jar/jwks_cache.go and internal/backchannel/deliverer.go:
// https-only, no redirects, body cap 64 KiB, request timeout 5 s,
// and a deny-list for loopback / link-local / RFC 1918 / IPv6 ULA.
// The DNS-time check uses [internal/jar.IsPrivateIP] so the three
// fetchers cannot drift independently. Embedders fronting their RPs
// behind private DNS opt in via [Option.AllowPrivateNetwork]; the
// public op-package surface routes the choice through the same
// configuration as the JAR fetcher.
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
