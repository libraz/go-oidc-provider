package jar

import "errors"

// descriptions is the sentinel-to-description catalogue [Description]
// walks, in the order it walks them.
//
// The order is load-bearing. Every sentinel in this package may unwrap
// onto [ErrParse] (the verifier wraps a parse failure with [fmt.Errorf]
// when reporting a more specific cause), so the parse class sits at the
// tail: walking top-down resolves the specific cause first and only
// falls through to "malformed" when nothing more precise matched.
//
// The catalogue lives here, beside the sentinels, rather than in each
// endpoint that renders one. Adding a sentinel without a description is
// then a single-file omission instead of a silent per-endpoint one — the
// three endpoints that consume JAR had drifted apart on exactly that
// axis before this table was shared.
//
//nolint:gochecknoglobals // immutable error-to-description catalogue.
var descriptions = []struct {
	sentinel error
	desc     string
}{
	{ErrAlgNotAllowed, "request object alg is not allowed"},
	{ErrSigInvalid, "request object signature is invalid"},
	{ErrIssMismatch, "request object iss does not match client_id"},
	{ErrAudMismatch, "request object aud does not match issuer"},
	{ErrClientIDMismatch, "client_id mismatch in request object"},
	{ErrExpired, "request object is expired or too old"},
	{ErrNotYetValid, "request object is not yet valid"},
	{ErrNestedRequest, "request object must not contain nested request parameters"},
	{ErrTypeInvalid, "request object typ header is not accepted"},
	{ErrJWKSFetch, "client jwks fetch failed"},
	{ErrNoMatchingJWK, "no matching client jwk"},
	{ErrJWKSConfigured, "client has no JWKs or JWKsURI"},
	{ErrJTIMissing, "request object missing jti"},
	{ErrJTIReplayed, "request object jti already consumed"},
	{ErrIATMissing, "request object missing iat"},
	{ErrEncryptionUnsupported, "encrypted request objects are not supported"},
	{ErrEncryptionAlgNotAllowed, "request object encryption alg/enc is not allowed"},
	{ErrDecryptFailed, "request object could not be decrypted"},
	{ErrParse, "request object is malformed"},
}

// Description returns a short operator-facing summary of a JAR
// verification failure, drawn from a small closed set so a log reader
// can correlate the wire response with the sentinel that produced it.
//
// The wrapped cause is never part of the result. It originates in
// third-party JOSE machinery whose wording is not stable across
// versions, and echoing it to the client would leak detail the OP has
// no reason to disclose.
//
// An error matching no sentinel yields a generic description rather
// than an empty string, so a caller can render the result
// unconditionally.
//
// Description says what went wrong, not how the endpoint answers: the
// OAuth wire code is the caller's decision, because the endpoints
// disagree on it legitimately. /authorize and /par have
// "invalid_request_object" available (RFC 9101 §6.1); CIBA Core §13
// enumerates a closed set of back-channel authentication error codes
// that does not include it, so its JAR failures surface as
// "invalid_request" carrying this description.
func Description(err error) string {
	for _, entry := range descriptions {
		if errors.Is(err, entry.sentinel) {
			return entry.desc
		}
	}
	return "request object verification failed"
}
