package jar

import "errors"

// Sentinel errors returned by [Parse], [Verifier.Verify], and [Merge].
// The HTTP layer maps these onto the OAuth wire codes
// "invalid_request_object" / "invalid_request" / "request_uri_not_supported"
// rather than echoing the wrapped cause; the surface visible to the
// client stays opaque while logs retain full diagnostic detail via
// [errors.Unwrap].
//
// Callers MUST branch on these via [errors.Is]; string-matching the
// wrapped cause is forbidden because the wrapped error originates in
// third-party JOSE machinery whose wording is not stable across
// versions.
var (
	// ErrParse signals that the input is not a syntactically valid
	// compact-serialised JWS, that its header is malformed, or that
	// the embedded payload could not be decoded as JSON. Pre-signature
	// failures converge on this sentinel.
	ErrParse = errors.New("jar: request object malformed")

	// ErrAlgNotAllowed signals that the JWS "alg" header advertises a
	// value outside the OP-wide allow-list or outside the per-client
	// pin in [op/store.Client.RequestObjectSigningAlg].
	ErrAlgNotAllowed = errors.New("jar: alg not allowed")

	// ErrSigInvalid signals that the JWS signature did not verify
	// against any key in the resolved client keyset. The class is
	// deliberately collapsed with "no key matched the kid header" so
	// an attacker cannot probe sub-causes through error timing.
	ErrSigInvalid = errors.New("jar: signature invalid")

	// ErrIssMismatch signals that the request object's "iss" claim is
	// missing or differs from the wire-level client_id. RFC 9101 §10.2
	// requires iss == client_id.
	ErrIssMismatch = errors.New("jar: iss does not match client_id")

	// ErrAudMismatch signals that the request object's "aud" claim is
	// missing or does not contain the OP issuer URL. FAPI 2.0 Message
	// Signing §5.6 mandates the audience check.
	ErrAudMismatch = errors.New("jar: aud does not match OP issuer")

	// ErrExpired signals that the "exp" claim is missing or already
	// past relative to the verifier's clock.
	ErrExpired = errors.New("jar: request object expired")

	// ErrNotYetValid signals that the "nbf" claim or the "iat" claim
	// is in the future beyond the verifier's tolerance window.
	ErrNotYetValid = errors.New("jar: request object not yet valid")

	// ErrClientIDMismatch signals that the wire-level client_id does
	// not match the value carried in the request object. RFC 9101
	// §6.1 requires the two to agree.
	ErrClientIDMismatch = errors.New("jar: client_id mismatch between wire and request object")

	// ErrNestedRequest signals that the request object itself carries
	// a "request" or "request_uri" claim. RFC 9101 §6.1 forbids
	// nesting; rejecting structurally also closes a recursive-fetch
	// vector at the request_uri endpoint.
	ErrNestedRequest = errors.New("jar: request object must not contain request or request_uri")

	// ErrJWKSFetch signals that the client's keyset could not be
	// retrieved from [op/store.Client.JWKsURI]. Wraps the underlying
	// transport / parse error.
	ErrJWKSFetch = errors.New("jar: jwks fetch failed")

	// ErrNoMatchingJWK signals that the verifier found no key in the
	// client's keyset matching the JWS "kid" header (or could not
	// pick a default key when the header was absent).
	ErrNoMatchingJWK = errors.New("jar: no matching jwk")

	// ErrJWKSConfigured signals that the client carries neither an
	// inline JWKs nor a JWKsURI, so the OP cannot verify a signed
	// request object on its behalf. Surfaced at the verifier so the
	// HTTP layer can return invalid_request_object rather than
	// 500-ing.
	ErrJWKSConfigured = errors.New("jar: client has no JWKs or JWKsURI")

	// ErrJTIMissing signals that the request object lacks a "jti"
	// claim under the strict default. RFC 9101 §10.8 names jti as
	// the replay-defence anchor; the verifier therefore rejects
	// jti-less request objects unless [VerifierConfig.AllowMissingJTI]
	// is set to admit legacy RPs.
	ErrJTIMissing = errors.New("jar: request object missing jti")

	// ErrJTIReplayed signals that the request object's "jti" claim
	// has already been consumed within the configured window. The
	// HTTP layer maps this onto invalid_request_object so an
	// attacker observing a replay attempt cannot distinguish it from
	// a malformed object via the error code.
	ErrJTIReplayed = errors.New("jar: request object jti already consumed")
)
