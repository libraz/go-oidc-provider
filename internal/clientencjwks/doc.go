// Package clientencjwks resolves the JOSE encryption recipient for a
// registered RP (relying party) so the OP can encrypt outbound
// responses (id_token, userinfo, JARM, introspection) to that
// client's public key.
//
// The package is the single source of truth for "given the client and
// the registered (alg, enc) pair, return the recipient
// [internal/jose.EncryptionRecipient] [internal/jose.EncryptNestedJWT]
// expects". The four outbound-encryption response paths share this
// resolver so the policy (alg / enc allow-list, JWKS sourcing, key
// selection) lives in one place.
//
// # Key sources
//
// The resolver consults the [op/store.Client] in this order:
//
//  1. Inline JWKs (RFC 7517 §5) — preferred when present because no
//     network round-trip is required.
//  2. JWKsURI (RFC 7517 §4.2) — fetched through the shared TTL cache
//     when inline JWKs is empty.
//
// A client carrying neither shape surfaces [ErrJWKSConfigured] so
// the caller can map it onto a clean wire-level error rather than a
// 500.
//
// Both shapes are resolved through [internal/rpjwks], the OP's single
// relying-party JWKS fetcher, so the cache budget, the body and member caps,
// the tolerance for unrepresentable members, and the negative-cache policy are
// the same ones the request-object and client-assertion paths apply.
//
// # SSRF posture
//
// Remote JWKS fetches go through the shared SSRF deny-list: the URL
// must use http or https, and the hostname (or every resolved
// address) must be outside the loopback / link-local / RFC 1918 / ULA
// / cloud-metadata ranges unless the resolver was constructed with
// [Config.AllowPrivateNetwork]. The gate fires both before the
// request is constructed and at dial time so a DNS-rebinding attacker
// cannot widen the surface.
//
// # Algorithm policy
//
// The (alg, enc) pair the caller passes MUST match the OP-wide JWE
// allow-list ([internal/jose.AllowedJWEAlgs] /
// [internal/jose.AllowedJWEEncs]); anything outside the list is
// rejected with [ErrAlgNotAllowed] before any JWKS lookup runs. The
// package never registers a new algorithm at runtime; extending the
// allow-list requires editing [internal/jose].
//
// # Sentinel errors
//
// Callers branch on the package sentinels via [errors.Is]:
//
//   - [ErrNoEncryptionConfigured] — the client did not register any
//     encryption metadata for this response path. Treated as
//     "encryption not requested" by the caller; not really an error.
//   - [ErrAlgNotAllowed] — alg or enc outside the OP allow-list.
//   - [ErrJWKSFetch] — remote JWKS fetch failed (HTTP error, body
//     cap, parse failure, SSRF refusal).
//   - [ErrJWKSConfigured] — the client carries neither inline JWKs
//     nor a JWKsURI.
//   - [ErrNoMatchingKey] — JWKS resolved but no key with `use=enc`
//     (or empty `use`) matched the requested alg.
package clientencjwks
