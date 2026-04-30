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

// Error implements the error interface. When [Error.Cause] is non-nil
// its message is appended so callers using fmt-style formatting still
// see the underlying reason, mirroring the pre-catalogue behaviour
// where wrappers used %w. The wire form sent to clients is built
// separately (see the endpoint encoders) and never includes Cause.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	head := e.Code
	if e.Description != "" {
		head = e.Code + ": " + e.Description
	}
	if e.Cause != nil {
		return head + ": " + e.Cause.Error()
	}
	return head
}

// Unwrap exposes the underlying cause to [errors.Is] and [errors.As].
func (e *Error) Unwrap() error { return e.Cause }

// Note: [Error] intentionally does not implement a custom Is method.
// Sentinel errors in this package are package-level pointer values
// (see [ErrIssuerRequired] et al.), and [errors.Is] uses pointer
// identity by default — the right behaviour, since two distinct
// sentinels can share an OAuth-style Code (e.g. "configuration_error")
// without being interchangeable. Use [IsClientError] / [IsServerError]
// for code-class predicates.

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
// that is not a syntactically valid absolute issuer URL: the scheme MUST be
// https (or http when the host is a loopback IP literal in 127.0.0.0/8 or
// [::1] for development), with a non-empty authority, no trailing slash, and
// no query or fragment, per OpenID Connect Discovery 1.0 §3 / FAPI 2.0 §5.4.
var ErrIssuerInvalid = &Error{
	Code:        codeConfiguration,
	Description: "issuer must be an absolute URL with no trailing slash, query, or fragment (https; http permitted only for loopback IP literals)",
}

// ErrKeysetRequired is returned by [New] when [WithKeyset] is not supplied or
// receives an empty slice. The library cannot mint signed tokens without at
// least one signing key.
var ErrKeysetRequired = &Error{
	Code:        codeConfiguration,
	Description: "WithKeyset is required",
}

// ErrCookieKeysRequired is returned by [New] when [WithCookieKey] /
// [WithCookieKeys] was not supplied but a configured grant requires the
// authorize endpoint to set encrypted cookies (e.g. AuthorizationCode).
// The default grant set includes AuthorizationCode, so the typical caller
// MUST supply at least one cookie key.
var ErrCookieKeysRequired = &Error{
	Code:        codeConfiguration,
	Description: "WithCookieKey/WithCookieKeys is required when the authorization_code grant is enabled",
}

// ErrDynamicRegistrationDisabled is returned by
// [Provider.IssueInitialAccessToken] and related operator-facing methods
// when the [Provider] was constructed without
// [WithDynamicRegistration]. The library does not silently no-op on the
// missing feature flag because IAT issuance is a control-plane operation
// that operators MUST be aware of.
var ErrDynamicRegistrationDisabled = &Error{
	Code:        codeConfiguration,
	Description: "WithDynamicRegistration is not configured",
}
