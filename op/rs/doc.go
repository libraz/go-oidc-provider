// Package rs verifies the access tokens an OAuth 2.0 resource server
// receives and answers a failed request with the challenge the
// specifications prescribe. It is the resource-server counterpart of the
// op package: op issues tokens, rs checks them.
//
// The package has two layers. A [Verifier] built by [New] turns an
// [*http.Request] into a verified [*Token] or an [*Error]; code that does
// not sit behind net/http calls it directly. [Verifier.Middleware] wraps a
// handler with that check plus the [Requirement] values (scope, acr,
// max_age) the route needs, writes the RFC 6750 §3 / RFC 9449 §7.1 /
// RFC 9470 §3 WWW-Authenticate challenge on failure, and hands the token
// to the next handler through [FromContext].
//
// What is checked:
//
//   - JWT access tokens (RFC 9068 §4): the typ header ("at+jwt" or
//     "application/at+jwt"), the signature against the issuer's JWK Set,
//     the required claims, iss, aud, exp and iat. The JWS alg must be one
//     of RS256, PS256, ES256 and EdDSA and, when the JWK declares an alg,
//     equal to it; "none" and the HMAC family are never accepted.
//   - Opaque access tokens, through RFC 7662 introspection when
//     [Config.Introspection] is set.
//   - Sender constraints: a token whose cnf carries "jkt" must arrive under
//     the DPoP scheme with a valid proof for the same key (RFC 9449 §7); a
//     token whose cnf carries "x5t#S256" must arrive over a connection
//     presenting the bound certificate (RFC 8705 §3). The cnf of an
//     introspection response is enforced exactly like the cnf of a JWT.
//
// What is not done: issuing DPoP nonces, caching introspection results,
// and retrying a step-up challenge on the client's behalf.
//
// Every outbound fetch (discovery, JWK Set, introspection) goes through
// the library's SSRF-hardened client: https is required, redirects are
// never followed, responses are size-capped, and private addresses are
// refused. [Config.AllowPrivateNetwork] admits private addresses, and
// plain http to a loopback IP literal for local development.
package rs
