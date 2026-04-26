// Package dpop implements RFC 9449 "OAuth 2.0 Demonstrating Proof of
// Possession" (DPoP). It provides:
//
//   - Parsing and verification of DPoP proof JWTs (RFC 9449 §4): header
//     "typ"/"alg" gating, public-key JWK in "jwk", "htm"/"htu"/"iat"/"jti"
//     claim validation, optional "ath" (access-token hash) binding for
//     resource calls (§4.3), and optional "nonce" (parsed but currently
//     ignored — server-supplied nonces are out of scope for v0.x).
//
//   - JWK thumbprint computation (RFC 7638) — the value bound to issued
//     tokens as the "jkt" member of the "cnf" claim (RFC 9449 §6).
//
//   - Replay protection backed by [store.ConsumedJTIStore] (RFC 9449
//     §11.1). The default replay window is 60 seconds, which matches the
//     "iat" tolerance.
//
// The package is consumed from the token endpoint, the resource server
// (userinfo) handler, and any future endpoint that wishes to require a
// proof of possession. Callers obtain a [*Verifier] once at startup and
// invoke [Verifier.Verify] per request; the verifier holds its
// configuration in immutable fields and is safe for concurrent use.
//
// # Algorithm policy
//
// v0.x accepts ES256 and EdDSA proofs. RS-family algorithms are rejected
// because RFC 9449 §4.1 strongly discourages them on the proof JWT;
// symmetric and "none" are rejected structurally because the input goes
// through [internal/jose.ParseSigned], which already enforces the project
// allow-list. ES384 is reserved for a future jose-package expansion.
package dpop
