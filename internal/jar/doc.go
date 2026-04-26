// Package jar implements RFC 9101 "OAuth 2.0 JWT-Secured Authorization
// Request" (JAR). It exposes:
//
//   - [Parse], which splits a compact-serialised JWS into a [Object]
//     (header + payload) without verifying the signature, so the caller
//     can extract "kid" / "alg" before fetching the keyset.
//
//   - [Verifier.Verify], which fetches the client's keyset (via the
//     [JWKSResolver]), verifies the signature, and validates the claims
//     ("iss" == client_id, "aud" == issuer, "exp" present and not past,
//     optional "nbf" / "iat" inside a window).
//
//   - [Merge], which folds a verified request object's claims onto the
//     wire-level [url.Values] per RFC 9101 §6.1: the request object
//     overrides the wire parameters, "request" / "request_uri" inside
//     the JWT are forbidden, and "client_id" MUST agree with the wire
//     value.
//
//   - The internal JWKS cache used by the default JWKSResolver, which
//     hardens the fetch with a hard timeout, a max-body cap, a strict
//     content-type check, an SSRF deny-list (loopback / link-local /
//     RFC 1918), and ETag-driven revalidation. Embedders that need to
//     reach a private network for JWKS URLs MUST opt in explicitly via
//     a future provider option (currently a TODO; the deny is hard-
//     coded).
//
// The package is consumed from the /authorize handler (request /
// request_uri) and the /par handler (request only). Callers obtain a
// [*Verifier] once at startup and invoke [Verifier.Verify] per request;
// the verifier holds its configuration in immutable fields and is safe
// for concurrent use.
//
// # Algorithm policy
//
// The verifier accepts whichever signing algorithms [internal/jose]
// admits (currently RS256, PS256, ES256, EdDSA). FAPI 2.0 Message
// Signing prefers PS256 / ES256 / EdDSA; RS256 is allowed for OIDC
// Core compatibility but operators SHOULD restrict per-client via
// [op/store.Client.RequestObjectSigningAlg]. The "none" algorithm and
// the HMAC family are rejected structurally because the input goes
// through [internal/jose.ParseSigned], which already enforces the
// project allow-list.
package jar
