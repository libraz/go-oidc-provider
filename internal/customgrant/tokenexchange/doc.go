// Package tokenexchange implements the RFC 8693 token-exchange
// grant_type as a thin wrapper over the custom-grant dispatcher.
// The wrapper satisfies the public op.CustomGrantHandler contract
// and lives behind op.RegisterTokenExchange; embedders never
// import this package directly.
//
// Implementation responsibilities:
//
//   - parse and verify subject_token / actor_token against the
//     active signing keyset, AccessTokenRegistry, and the opaque
//     access-token store;
//   - normalise the requested audience per RFC 8707 §2 and
//     intersect with the calling client's allowed resources;
//   - intersect the requested scope with the subject_token's scope
//     and the client's allowed scopes. An id_token carries no scope
//     claim, so its bound is the persisted consent recorded for the
//     (subject, client) pair it names — which also makes withdrawn
//     consent close the exchange before the id_token expires;
//   - cap the issued TTL at min(handler request, subject_token
//     remaining, global access-token cap);
//   - build the act-claim chain on the provider side, mandatory
//     whenever the actor differs from the subject, capped at five
//     levels of nesting;
//   - rebind the issued token's cnf to the request's verified
//     DPoP proof or mTLS leaf certificate (not the subject_token's
//     original binding);
//   - emit the audit-event family token_exchange.* documented in
//     the provider's audit catalogue.
//
// The package is intentionally small. Every cross-cutting policy
// the provider already enforces for built-in grants (scope subset,
// audience filter, TTL ceiling, reserved-claim filter, panic
// recovery) reuses the customgrant dispatcher's existing seam; the
// only new code in this directory is the token-exchange-specific
// verification and chain construction.
package tokenexchange
