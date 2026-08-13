// Package introspectendpoint implements the OAuth 2.0 Token Introspection
// endpoint defined by RFC 7662.
//
// A client that authenticates (typically a resource server acting as a
// protected resource) POSTs the token it wants inspected to /introspect,
// using the same machinery the token endpoint uses. RFC 7662 §2.1
// requires the endpoint to authenticate its caller, so a client
// registered with no authentication method is refused: introspection
// discloses the token's subject, scope and expiry, which is not a
// disclosure an unauthenticated caller may make. The
// handler resolves the token (auto-detecting JWT vs. opaque), enforces the
// same-client-only authorization policy described below, and responds with
// the canonical introspection JSON per RFC 7662 §2.2.
//
// # Token resolution
//
// Two paths dispatched on token shape:
//
//   - JWT-shaped (three base64 segments separated by "."): treated as a
//     JWT-formatted access token (RFC 9068). Verified through
//     internal/tokens.AccessTokenVerifier (issuer + signature + exp +
//     iat). On success its claims are projected onto the response;
//     audience is intentionally NOT validated, mirroring the same choice
//     made by internal/userinfo (the resource server owns the audience
//     policy).
//   - Otherwise: opaque. Looked up in [op/store.RefreshTokenStore.Find].
//     A record that is unconsumed and unexpired projects onto the
//     response; anything else collapses onto inactive.
//
// Opaque access tokens (RFC 7662 §2.1 anticipates them) are NOT a v1.0
// feature: the library only mints JWT-shaped access tokens, so the JWT
// branch handles every access-token introspection request. An embedder
// that issues opaque access tokens out-of-band would need to wrap this
// handler.
//
// # token_type_hint
//
// The hint is honoured to skip an unnecessary lookup, but the handler
// always falls through to the other path on miss per RFC 7662 §2.1
// ("If the server is unable to locate the token using the given hint,
// it MUST extend its search across all of its supported token types").
//
// # Authorization model — same-client-only, with scoped delegation
//
// RFC 7662 §2.1 leaves the authorization policy to the deployment. The
// default is the most conservative posture: the authenticated client_id
// MUST match the introspected token's client_id; otherwise the response
// is inactive.
//
// An embedder that runs a resource server opts out of that default by
// naming the resource server's client_id on the resource-server metadata
// it registers, which reaches the handler as [Deps.IntrospectionDelegates].
// A named client may introspect an access token issued to any client
// provided the token's audience is that resource — which is RFC 7662's
// canonical deployment, and without it a resource server that follows
// this OP's own metadata document to the introspection endpoint learns
// nothing about the tokens presented to it.
//
// The delegation is deliberately narrow in two ways. It is scoped to the
// audience, so registering a gateway for one API never becomes blanket
// visibility over every client's tokens. And it never covers refresh
// tokens: a refresh token is the client's own credential rather than
// something a resource server is presented with, so its owner check
// stays absolute.
//
// # Inactive vs. error
//
// Errors that fire BEFORE successful client authentication (malformed
// body, missing token parameter, missing or bad client credentials) emit
// the RFC 6749 §5.2 envelope on HTTP 400 / 401. Errors AFTER successful
// client auth (token doesn't validate, doesn't belong to the
// authenticated client, expired, revoked) emit `{"active": false}` on
// HTTP 200 — RFC 7662 §2.2 forbids leaking which sub-class of failure
// produced the rejection.
//
// # Caching headers
//
// RFC 7662 §4 mandates Cache-Control: no-store on every successful
// response; the handler stamps it unconditionally (success and error)
// for uniformity with /token and /par.
//
// # Layering
//
// The package is a thin orchestration over four collaborators:
//
//   - internal/clientauth for client authentication;
//   - internal/tokens.AccessTokenVerifier for JWT introspection;
//   - [op/store.RefreshTokenStore] for opaque introspection;
//   - internal/timex (via the package-local Clock) for wall-clock reads.
//
// A nil [Deps.RefreshTokens] disables refresh-token introspection only:
// such a token projects onto inactive. The opaque access-token path
// runs off [Deps.OpaqueAccessTokens] independently, and JWT
// introspection consults neither store.
//
// # JWT-formatted responses (RFC 9701)
//
// When the introspecting client has preregistered
// [op/store.Client.IntrospectionSignedResponseAlg], or the request's
// Accept header prefers application/token-introspection+jwt over
// application/json, the response is emitted as a compact-serialised
// JWS instead of JSON. The JWT carries the OP's iss, the requesting
// client_id as aud, the wall-clock iat, and the RFC 7662 §2.2 body
// nested under the "token_introspection" claim. The JWS header sets
// "typ": "token-introspection+jwt". v1.0 signs with ES256 only;
// discovery advertises the alg list at
// "introspection_signing_alg_values_supported".
package introspectendpoint
