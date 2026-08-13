// Package revokeendpoint implements the OAuth 2.0 Token Revocation
// endpoint defined by RFC 7009.
//
// A confidential or public client POSTs a token it wants to invalidate
// to /revoke, authenticating with the same machinery the token endpoint
// uses. The handler resolves the token (auto-detecting JWT vs. opaque),
// applies the same-client-only authorization policy described below,
// and responds with HTTP 200 and an empty body per RFC 7009 §2.2.
//
// # Token resolution
//
// Two paths dispatched on token shape:
//
//   - JWT-shaped (three base64 segments separated by "."): treated as a
//     JWT-formatted access token (RFC 9068). Verified through
//     internal/tokens.AccessTokenVerifier (issuer + signature + exp +
//     iat). On a successful verify the handler matches the token's
//     "client_id" against the authenticated client; on a match the
//     revocation is recorded in the shape
//     [store.AccessTokenRevocationStrategy] selects — a grant tombstone
//     by default, or a per-JTI record — so a resource server that
//     consults the OP stops honouring the token.
//   - Otherwise: opaque. Looked up in [op/store.RefreshTokenStore.Find].
//     A record whose ClientID matches the authenticated client triggers
//     a parent-walk to the chain root followed by a call to
//     [op/store.RefreshTokenStore.RevokeChain]; the entire rotation
//     chain is invalidated in a single best-effort store transaction.
//
// Opaque access tokens (RFC 7009 §2.1 anticipates them) are handled
// too: an OP configured for [op.AccessTokenFormatOpaque] resolves them
// through [Deps.OpaqueAccessTokens], which is a separate substore from
// the refresh-token one. An embedder that issues access tokens
// out-of-band, outside either store, would still need to wrap this
// handler.
//
// # token_type_hint
//
// The hint is honoured to skip an unnecessary lookup, but the handler
// always falls through to the other path on miss per RFC 7009 §2.1
// ("If the server is unable to locate the token using the given hint,
// it MUST extend its search across all of its supported token types").
// An unrecognised hint defaults to the same order as an absent hint
// (try JWT first when the shape matches, otherwise opaque).
//
// # Authorization model — same-client-only
//
// RFC 7009 §2.1 leaves the authorization policy partially ambiguous:
// the spec recommends that the AS only honour revocation from the
// client to which the token was issued, but does not define the
// observable behaviour when a different client presents the token.
// v1.0 adopts the most conservative posture: cross-client revocation
// is silently ignored. The unauthenticated revoker sees the same HTTP
// 200 with an empty body as a legitimate one — RFC 7009 §2.2 forbids
// leaking the failure mode through the status code, and treating the
// state mutation symmetrically (both succeed-shaped) prevents an
// attacker from probing token ownership through the revocation
// endpoint.
//
// # JWT access-token revocation is a no-op
//
// A JWT access token stays cryptographically valid until its "exp"
// claim is reached: revocation is recorded on the OP, not stamped into
// the token. A resource server that validates the signature offline and
// never introspects therefore keeps honouring the token for the
// remainder of its lifetime, so access-token TTL still bounds the
// worst-case revocation lag for that deployment shape. The library's
// defaults (5–10 minutes) are well within the FAPI 2.0 guidance.
//
// Refresh-token revocation, by contrast, is durable: the entire
// rotation chain is consumed before the handler returns 200, and any
// subsequent refresh attempt against any token in the chain fails with
// invalid_grant.
//
// # Errors before successful client authentication
//
// Errors that fire BEFORE successful client authentication (malformed
// body, missing token parameter, missing or bad client credentials)
// emit the RFC 6749 §5.2 envelope on HTTP 400 / 401. Errors AFTER
// successful client auth (token does not exist, does not belong to the
// authenticated client, already consumed) collapse onto a 200 — RFC
// 7009 §2.2 explicitly forbids leaking which sub-class of failure
// produced the rejection.
//
// # Caching headers
//
// RFC 7009 does not mandate cache headers, but the handler stamps
// Cache-Control: no-store and Pragma: no-cache on every response
// (success and error) for uniformity with /token, /par, and
// /introspect. The empty success body carries no Content-Type header
// because there is no media to type.
//
// # Layering
//
// The package is a thin orchestration over three collaborators:
//
//   - internal/clientauth for client authentication;
//   - internal/tokens.AccessTokenVerifier for JWT revocation
//     acknowledgement;
//   - [op/store.RefreshTokenStore] for refresh-token chain revocation.
//
// A nil [Deps.RefreshTokens] disables refresh-token revocation only:
// such a request silently 200s, as RFC 7009 §2.2 requires. The opaque
// access-token path runs off [Deps.OpaqueAccessTokens] independently,
// and JWT acknowledgement consults neither store.
package revokeendpoint
