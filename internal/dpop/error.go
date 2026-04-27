package dpop

import "errors"

// Sentinel errors returned by [Verifier.Verify] and the underlying proof
// parser. The HTTP layer maps these onto WWW-Authenticate challenges
// (RFC 9449 §7.1: error="invalid_dpop_proof" / "invalid_token") rather
// than echoing the wrapped cause, so the surface visible to the client
// stays opaque while logs retain full diagnostic detail via
// [errors.Unwrap].
//
// Callers MUST branch on these via [errors.Is]; string-matching the
// wrapped cause is forbidden because the wrapped error originates in
// third-party JOSE machinery whose wording is not stable across
// versions.
var (
	// ErrProofMalformed signals that the input is not a syntactically
	// valid compact-serialised JWS, that its "typ" header is not
	// "dpop+jwt", that its "alg" is outside the allow-list, or that
	// the embedded "jwk" header is missing / not a public key. The
	// taxonomy mirrors [internal/tokens.ErrAccessTokenMalformed]:
	// every pre-signature failure converges on this sentinel.
	ErrProofMalformed = errors.New("dpop: proof malformed")

	// ErrProofSignature signals that the JWS signature did not verify
	// against the JWK embedded in the proof header. The class is
	// deliberately collapsed with "key shape unusable" so an attacker
	// cannot probe sub-causes through error timing.
	ErrProofSignature = errors.New("dpop: proof signature invalid")

	// ErrProofIatWindow signals that the "iat" claim is outside the
	// configured tolerance window. RFC 9449 §4.3 leaves the exact
	// width to the server; this package defaults to ±60 seconds.
	ErrProofIatWindow = errors.New("dpop: proof iat outside acceptable window")

	// ErrProofReplayed signals that the "jti" claim has already been
	// observed within the replay window. The store-side mark happens
	// atomically inside [Verifier.Verify]; once this error fires the
	// caller has no remediation other than rejecting the request.
	ErrProofReplayed = errors.New("dpop: proof jti already used")

	// ErrProofHTMMismatch signals that the "htm" claim does not equal
	// the request method.
	ErrProofHTMMismatch = errors.New("dpop: proof htm does not match request method")

	// ErrProofHTUMismatch signals that the "htu" claim does not equal
	// the canonical request URL (scheme + host + path; query / fragment
	// stripped per RFC 9449 §4.3).
	ErrProofHTUMismatch = errors.New("dpop: proof htu does not match request url")

	// ErrProofATHMismatch signals that the "ath" claim is missing when
	// an access token is presented OR that it does not equal the
	// SHA-256 base64url-no-pad hash of that token.
	ErrProofATHMismatch = errors.New("dpop: proof ath does not match access token")

	// ErrProofMissingJTI signals that the "jti" claim is absent. The
	// claim is mandatory under RFC 9449 §4.2; without it the replay
	// store has nothing to mark.
	ErrProofMissingJTI = errors.New("dpop: proof missing jti")

	// ErrProofNonceMissing signals that the verifier has been
	// configured with a [NonceVerifier] but the proof does not carry a
	// "nonce" claim. RFC 9449 §8 / §9 prescribes a 401 / 400 response
	// with "WWW-Authenticate: DPoP error=\"use_dpop_nonce\"" and a
	// fresh "DPoP-Nonce" header so the client can retry. The HTTP
	// layer translates this sentinel onto that wire form; the
	// verifier itself only signals the condition.
	ErrProofNonceMissing = errors.New("dpop: proof missing nonce")

	// ErrProofNonceInvalid signals that the proof carries a "nonce"
	// claim but it is not currently acceptable to the configured
	// [NonceVerifier]. The wire response is identical to the
	// missing-nonce case (RFC 9449 §8 collapses the two onto the same
	// challenge) so callers may inspect either sentinel through a
	// single [errors.Is] check, but the two are kept distinct here so
	// audit logs can tell "stale" apart from "absent".
	ErrProofNonceInvalid = errors.New("dpop: proof nonce not acceptable")
)
