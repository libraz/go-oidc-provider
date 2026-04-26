// Package authorize implements the pure-validation layer for the OAuth 2.0 /
// OpenID Connect Core 1.0 authorization endpoint. It parses an incoming
// authorization request into a normalised [Request] and, against a registered
// [store.Client], decides whether the request is structurally and policy-wise
// admissible.
//
// The package never reads the wall clock, never performs I/O, and never
// resolves a session. Those couplings live in the HTTP layer that composes
// this validator with session resolution and the [interaction.Driver].
//
// # Wire mapping
//
// Each sentinel returned by the package carries an OAuth wire code (one of
// "invalid_request", "unsupported_response_type", "invalid_scope") via the
// [Error] type. The HTTP layer translates those codes uniformly: the
// validation errors that fire BEFORE the redirect_uri has been confirmed
// against the client are not safe to redirect on (the redirect target is not
// trusted yet); errors that fire AFTER may propagate to the RP via a
// redirect with the OAuth error parameters. [IsRedirectSafe] reports the
// boundary so callers do not need to remember which sentinel sits on which
// side.
package authorize

import "errors"

// Error is a wire-coded validation failure. Code is the OAuth error
// identifier ("invalid_request", "invalid_scope", ...) and Description is a
// human-readable string suitable for the error_description query parameter.
//
// Sentinels declared in this file are exposed as singleton *Error pointers;
// callers MUST compare with [errors.Is] rather than direct equality so that
// future wrapping does not break the check. The [Error.Is] method preserves
// pointer identity through wrapping.
type Error struct {
	// Code is the OAuth wire error identifier.
	Code string

	// Description is the human-readable explanation. It is intentionally
	// short and free of sensitive information; the HTTP layer is free to
	// place it directly in error_description.
	Description string
}

// Error implements the [error] interface.
func (e *Error) Error() string {
	return e.Code + ": " + e.Description
}

// Is reports whether target is the same sentinel as e. The check is pointer
// identity by design: every sentinel in this package is a distinct singleton,
// so equality on the pointer means "same sentinel" without false positives
// across wire codes that happen to share a Code.
func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && other == e
}

// newErr builds a sentinel [Error]. It is private so the catalogue of wire
// codes is closed at the package boundary; callers are expected to compare
// against the exported variables below rather than fabricate their own.
func newErr(code, description string) *Error {
	return &Error{Code: code, Description: description}
}

// Sentinel errors. Each maps to a single OAuth wire code so the HTTP layer
// can translate uniformly. The grouping below also documents the
// redirect-safety boundary enforced by [IsRedirectSafe]:
//
//   - ErrClientIDRequired, ErrRedirectURIRequired, ErrRedirectURIInvalid:
//     fired BEFORE the redirect target is trusted. Callers MUST NOT redirect.
//   - Every other sentinel: fired AFTER redirect_uri verification. Callers
//     MAY redirect to the RP with the OAuth error parameters.
var (
	// ErrClientIDRequired indicates the request omitted client_id. Maps to
	// invalid_request. NOT redirect-safe — without a client we cannot trust
	// any redirect_uri.
	ErrClientIDRequired = newErr("invalid_request", "client_id is required")

	// ErrResponseTypeUnsupported indicates the response_type is not "code".
	// The library only ships the Code flow in v1.0; Implicit / Hybrid are
	// rejected. Maps to unsupported_response_type.
	ErrResponseTypeUnsupported = newErr("unsupported_response_type", "response_type must be code")

	// ErrRedirectURIRequired indicates redirect_uri was omitted. Maps to
	// invalid_request. NOT redirect-safe.
	ErrRedirectURIRequired = newErr("invalid_request", "redirect_uri is required")

	// ErrRedirectURIInvalid indicates redirect_uri did not exact-match any
	// entry in the client's RedirectURIs (RFC 6749 §3.1.2.2; the [store.Client]
	// godoc forbids prefix / case folding). Maps to invalid_request. NOT
	// redirect-safe.
	ErrRedirectURIInvalid = newErr("invalid_request", "redirect_uri is not registered for this client")

	// ErrScopeMissingOpenID indicates the scope parameter did not include
	// "openid". The library only services OIDC requests at this endpoint.
	// Maps to invalid_scope.
	ErrScopeMissingOpenID = newErr("invalid_scope", "openid scope is required")

	// ErrScopeNotPermitted indicates the request asked for at least one
	// scope that is not present in the client's registered Scopes. Maps to
	// invalid_scope.
	ErrScopeNotPermitted = newErr("invalid_scope", "scope is not granted to this client")

	// ErrScopeClientNotAllowed indicates the request asked for a scope
	// whose AllowedClients allowlist does not include the requesting
	// client_id. Maps to invalid_scope per RFC 6749 §5.2.
	ErrScopeClientNotAllowed = newErr("invalid_scope", "scope is restricted to a different client")

	// ErrPKCERequired indicates the client omitted code_challenge. PKCE is
	// mandatory regardless of client type per the product design
	// (docs/plans/002-product-design.md §A.12.3). Maps to invalid_request.
	ErrPKCERequired = newErr("invalid_request", "code_challenge is required")

	// ErrPKCEMethodUnsupported indicates code_challenge_method was absent
	// or not "S256". The default of "plain" required by RFC 7636 is
	// rejected by policy. Maps to invalid_request.
	ErrPKCEMethodUnsupported = newErr("invalid_request", "code_challenge_method must be S256")

	// ErrPKCEFormat indicates code_challenge is not a 43-character
	// base64url-without-padding string. Maps to invalid_request.
	ErrPKCEFormat = newErr("invalid_request", "code_challenge format is invalid")

	// ErrPromptInvalid indicates prompt contains a value other than the
	// four recognised by OIDC Core §3.1.2.1 ("none", "login", "consent",
	// "select_account"). Maps to invalid_request.
	ErrPromptInvalid = newErr("invalid_request", "prompt contains an unrecognised value")

	// ErrPromptConflict indicates prompt=none was combined with other
	// prompt values; OIDC Core §3.1.2.1 requires "none" to appear alone.
	// Maps to invalid_request.
	ErrPromptConflict = newErr("invalid_request", "prompt=none cannot combine with other prompts")

	// ErrMaxAgeInvalid indicates max_age is present but not parseable as a
	// non-negative integer. Maps to invalid_request.
	ErrMaxAgeInvalid = newErr("invalid_request", "max_age must be a non-negative integer")

	// ErrStateRequired indicates the state parameter was omitted. OIDC
	// Core RECOMMENDS state; the library upgrades that to MUST per FAPI
	// 2.0. Maps to invalid_request.
	ErrStateRequired = newErr("invalid_request", "state is required")

	// ErrNonceRequired indicates the nonce parameter was omitted. The OP
	// always emits OIDC id_tokens here, so nonce is mandatory. Maps to
	// invalid_request.
	ErrNonceRequired = newErr("invalid_request", "nonce is required")

	// ErrDuplicateParameter indicates a single-valued request parameter
	// appeared more than once with conflicting values, or a multi-valued
	// parameter appeared in more than one url.Values entry. Maps to
	// invalid_request.
	ErrDuplicateParameter = newErr("invalid_request", "request parameter appeared more than once with different values")

	// ErrInvalidRequestURI indicates the request_uri value presented at
	// /authorize is unknown, expired, already consumed, or otherwise
	// unredeemable. Maps to invalid_request_uri (RFC 9126 §2.3). NOT
	// redirect-safe — without a trusted PAR record we cannot trust the
	// redirect_uri the client claims either.
	ErrInvalidRequestURI = newErr("invalid_request_uri", "request_uri is invalid, expired, or already consumed")
)

// IsRedirectSafe reports whether err arose AFTER redirect_uri validation
// passed and is therefore safe to surface to the RP via a redirect with the
// OAuth error parameters. Errors that fire before the redirect target is
// trusted (missing client_id, missing or unregistered redirect_uri) return
// false: the HTTP layer MUST render an inline error page in those cases.
//
// Errors not produced by this package return false; the caller has not
// validated, so we cannot make any redirect-safety claim.
func IsRedirectSafe(err error) bool {
	if err == nil {
		return false
	}
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	switch e {
	case ErrClientIDRequired, ErrRedirectURIRequired, ErrRedirectURIInvalid, ErrInvalidRequestURI:
		return false
	default:
		return true
	}
}
