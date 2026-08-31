// Package dpop implements RFC 9449 "OAuth 2.0 Demonstrating Proof of
// Possession" (DPoP). It provides:
//
//   - Parsing and verification of DPoP proof JWTs (RFC 9449 §4): header
//     "typ"/"alg" gating, public-key JWK in "jwk", "htm"/"htu"/"iat"/"jti"
//     claim validation, optional "ath" (access-token hash) binding for
//     resource calls (§4.3), and "nonce" (§8 / §9), which is enforced
//     when the verifier is configured with a [NonceVerifier] and
//     parsed but unread otherwise.
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
// Endpoints that authenticate a client around the proof drive the whole
// per-request lifecycle — presence test, stateless verification, client
// authentication, replay commit, and the wire mapping of every [Err*]
// sentinel — through [Gate.Authenticate] rather than assembling the
// phases themselves, so the ordering and the error envelope stay
// identical across them.
//
// # Algorithm policy
//
// The verifier accepts ES256, EdDSA, and PS256 proofs. RS256 (PKCS#1
// v1.5) is rejected — modern profiles steer RSA toward PSS and the OFCS
// negative-test pipeline relies on the rejection; symmetric and "none"
// are rejected structurally because the input goes through
// internal/jose.ParseSigned, which already enforces the project
// allow-list. ES384 is reserved for a future jose-package expansion.
package dpop
