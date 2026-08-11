// Package rpjwks is the single relying-party JWKS fetcher. Every OP surface
// that has to turn a client's registered jwks_uri into keys — request-object
// verification, private_key_jwt client authentication, and outbound response
// encryption — resolves it through one [Fetcher] so the security posture is
// stated once instead of per call site.
//
// # What the fetcher owns
//
//   - The SSRF envelope, delegated to internal/securefetch: scheme allow-list,
//     URL-time and dial-time deny-list, per-request timeout.
//   - One body cap and one member cap, so a hostile keyset cannot grow the
//     parse cost or the resident set without bound.
//   - Member-wise decoding (RFC 7517 §5): a key this build cannot represent is
//     dropped rather than failing the document, so an RP that publishes an
//     X25519 key beside its signing key stays usable.
//   - A bounded TTL/LRU cache with HTTP conditional-GET revalidation, so a
//     rotation propagates without re-downloading an unchanged document.
//   - Negative caching of upstream failures, and a per-URL throttle on the
//     forced refresh, so neither path amplifies inbound requests into outbound
//     ones.
//
// # Caller isolation
//
// The outbound round-trip runs under a context detached from the caller's
// request. Concurrent fetches for one URL collapse onto a single flight, so the
// winner's context would otherwise be the one every collapsed waiter depends on
// — an unauthenticated peer could abort a fetch everyone else is waiting for by
// disconnecting. A caller that gives up abandons only its own wait; the fetch
// completes into the cache for the next caller and a cancellation is never
// negative-cached.
//
// # Error taxonomy
//
// The calling package keeps its own sentinel: [Config.FetchError] is the error
// every failure wraps, so `errors.Is(err, jar.ErrJWKSFetch)` and
// `errors.Is(err, clientencjwks.ErrJWKSFetch)` stay distinct over one shared
// implementation. A zero [Config.FetchError] falls back to [ErrFetch].
package rpjwks
