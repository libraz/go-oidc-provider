package op

import "errors"

// Error is the canonical error type returned by [Provider]-related code paths
// that cross the public API boundary. It carries an OAuth/OIDC-style code,
// a short description suitable for logging, and an optional wrapped cause.
//
// Construct Error values through the package-level helpers (e.g.
// [errInvalidRequest]) rather than instantiating this struct directly so
// that the catalog stays the single source of truth.
type Error struct {
	// Code is the OAuth-style machine-readable error code (e.g.
	// "invalid_request"). It MUST come from the catalog defined in this
	// file; ad-hoc codes are forbidden.
	Code string

	// Description is a human-readable, non-localised hint for operators.
	// It MUST NOT contain sensitive material (tokens, raw inputs).
	Description string

	// Cause is an optional underlying error. It is exposed via [errors.Is]
	// and [errors.Unwrap] but is never sent to the client.
	Cause error
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

// Unwrap exposes the underlying cause to [errors.Is] and [errors.As].
func (e *Error) Unwrap() error { return e.Cause }

// Is reports whether target is an [*Error] with the same Code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	if !ok {
		return false
	}
	return t.Code == e.Code
}

// IsClientError reports whether err is a 4xx-class [*Error] caused by client
// input (invalid_request, invalid_grant, unauthorized_client, etc.).
//
// Stable since v0.1.
func IsClientError(err error) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	switch e.Code {
	case codeInvalidRequest,
		codeInvalidClient,
		codeInvalidGrant,
		codeUnauthorizedClient,
		codeUnsupportedGrantType,
		codeUnsupportedResponseType,
		codeInvalidScope,
		codeAccessDenied:
		return true
	default:
		return false
	}
}

// IsServerError reports whether err is a 5xx-class [*Error] caused by server
// or configuration faults.
//
// Stable since v0.1.
func IsServerError(err error) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	switch e.Code {
	case codeServerError, codeTemporarilyUnavailable, codeConfiguration:
		return true
	default:
		return false
	}
}

// Catalog of error codes. Keep alphabetised within each section.
const (
	// 4xx-class codes (caller is at fault).
	codeAccessDenied            = "access_denied"
	codeInvalidClient           = "invalid_client"
	codeInvalidGrant            = "invalid_grant"
	codeInvalidRequest          = "invalid_request"
	codeInvalidScope            = "invalid_scope"
	codeUnauthorizedClient      = "unauthorized_client"
	codeUnsupportedGrantType    = "unsupported_grant_type"
	codeUnsupportedResponseType = "unsupported_response_type"

	// 5xx-class codes (operator is at fault).
	codeConfiguration          = "configuration_error"
	codeServerError            = "server_error"
	codeTemporarilyUnavailable = "temporarily_unavailable"
)

// ErrIssuerRequired is returned by [New] when [WithIssuer] is not supplied.
var ErrIssuerRequired = &Error{
	Code:        codeConfiguration,
	Description: "WithIssuer is required",
}

// ErrStoreRequired is returned by [New] when [WithStore] is not supplied.
// The library does not own user accounts or persistence and therefore cannot
// run without a caller-provided storage backend.
var ErrStoreRequired = &Error{
	Code:        codeConfiguration,
	Description: "WithStore is required",
}

// ErrIssuerInvalid is returned by [New] when [WithIssuer] receives a value
// that is not a syntactically valid absolute https URL without a query or
// fragment, per OpenID Connect Discovery 1.0 §3.
var ErrIssuerInvalid = &Error{
	Code:        codeConfiguration,
	Description: "issuer must be an absolute https URL with no query or fragment",
}
