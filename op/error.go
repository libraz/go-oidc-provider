package op

import "errors"

// Error is the canonical error type returned by [Provider]-related code paths
// that cross the public API boundary. It carries an OAuth/OIDC-style code,
// a short description suitable for logging, and an optional wrapped cause.
//
// Construct Error values through the package-level helpers
// ([newConfigurationError]; future code-class helpers SHOULD follow the
// same shape) rather than instantiating this struct directly so that
// the catalog stays the single source of truth. New code-class factories
// MUST live in this file so the closed catalog of error codes stays
// auditable from one location.
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

// ErrCookieKeysRequired is returned by [New] when [WithCookieKeys] was
// not supplied but a configured grant requires the authorize endpoint
// to set encrypted cookies (e.g. AuthorizationCode). The default grant
// set includes AuthorizationCode, so the typical caller MUST supply at
// least one cookie key.
var ErrCookieKeysRequired = &Error{
	Code:        codeConfiguration,
	Description: "WithCookieKeys is required when the authorization_code grant is enabled",
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

// ErrPairwiseSaltTooShort is returned by [New] when [WithPairwiseSubject]
// receives a salt shorter than the documented minimum (32 bytes / 256
// bits). The library refuses to derive subject identifiers from a salt
// that does not provide adequate resistance to precomputation; the
// validator runs at construction time so the failure mode is build-up
// rather than a runtime surprise.
var ErrPairwiseSaltTooShort = &Error{
	Code:        codeConfiguration,
	Description: "WithPairwiseSubject salt must be at least 32 bytes",
}

// ErrSubjectGeneratorRequired is returned by [New] when
// [WithSubjectGenerator] receives a nil generator. The library does not
// silently fall back to the UUIDv7 default in that case because a nil
// generator usually signals a wiring bug (for example, a builder
// returning the zero value of an interface) and silently masking it
// would let pairwise-intended deployments emit public-style subjects.
var ErrSubjectGeneratorRequired = &Error{
	Code:        codeConfiguration,
	Description: "WithSubjectGenerator requires a non-nil SubjectGenerator",
}

// ErrSubjectInputEmpty is returned by [SubjectGenerator] implementations
// when both [SubjectGeneratorInput.InternalUserID] and
// [SubjectGeneratorInput.Federated] are zero. The library treats it as
// a server-side configuration error: the issuance pipeline is expected
// to populate exactly one of the two fields before invoking the
// generator.
var ErrSubjectInputEmpty = &Error{
	Code:        codeServerError,
	Description: "subject generator input has no InternalUserID and no Federated identifier",
}

// ErrPairwiseSectorUnresolved is returned by the pairwise
// [SubjectGenerator] when the requesting client carries no
// sector_identifier_uri AND has more than one (or zero) registered
// redirect_uri host from which a sector can be derived. OIDC Core 1.0
// §5 requires a single sector for stable pairwise output; the library
// refuses to invent one because two RPs sharing the OP would otherwise
// collide on subject values.
var ErrPairwiseSectorUnresolved = &Error{
	Code:        codeServerError,
	Description: "pairwise subject requires sector_identifier_uri or a single redirect_uri host",
}

// newConfigurationError returns a fresh configuration_error wrapping
// the supplied description and (optional) cause. The factory exists so
// option-site code does not have to repeat the literal struct shape on
// every error path; new configuration errors SHOULD route through it
// rather than instantiating [Error] directly. Future code-class
// factories (e.g. for invalid_request / invalid_grant when option- or
// parser-side code starts emitting them) SHOULD live alongside this
// helper so the catalog stays single-source.
func newConfigurationError(description string, cause error) *Error {
	return &Error{
		Code:        codeConfiguration,
		Description: description,
		Cause:       cause,
	}
}
