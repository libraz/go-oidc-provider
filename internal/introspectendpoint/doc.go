// Package introspectendpoint implements the OAuth 2.0 Token Introspection
// endpoint defined by RFC 7662.
//
// A confidential or public client (typically a resource server acting as a
// protected resource) POSTs the token it wants inspected to /introspect,
// authenticating with the same machinery the token endpoint uses. The
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
//     [internal/tokens.AccessTokenVerifier] (issuer + signature + exp +
//     iat). On success its claims are projected onto the response;
//     audience is intentionally NOT validated, mirroring the same choice
//     made by [internal/userinfo] (the resource server owns the audience
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
// # Authorization model — same-client-only
//
// RFC 7662 §2.1 leaves the authorization policy to the deployment. v1.0
// adopts the most conservative posture: the authenticated client_id MUST
// match the introspected token's client_id; otherwise the response is
// inactive. This aligns with FAPI 2.0 where introspection is a per-
// resource-server affair. An embedder who needs cross-client
// introspection (a single resource server inspecting tokens from many
// clients) wraps the handler — there is no config knob in v1.0.
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
//   - [internal/clientauth] for client authentication;
//   - [internal/tokens.AccessTokenVerifier] for JWT introspection;
//   - [op/store.RefreshTokenStore] for opaque introspection;
//   - [internal/timex] (via the package-local Clock) for wall-clock reads.
//
// A nil [Deps.RefreshTokens] disables the opaque path entirely: opaque
// tokens always project onto inactive. JWT introspection still functions
// because it does not consult the refresh-token store.
//
// TODO(introspect-jwt): JWT-formatted introspection responses (FAPI 2.0
// Message Signing) are deferred to Task #31. The current package emits
// JSON only; the metadata fields
// "introspection_signing_alg_values_supported",
// "introspection_encryption_alg_values_supported", and
// "introspection_encryption_enc_values_supported" are not yet advertised
// in discovery.
package introspectendpoint
