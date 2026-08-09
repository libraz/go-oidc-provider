package op

import (
	"encoding/json"
	"errors"
	"net/http"
)

// Error is the canonical error type returned by [Provider]-related code paths
// that cross the public API boundary. It carries an OAuth/OIDC-style code,
// a short description suitable for logging, and an optional wrapped cause.
//
// The configuration errors [New] returns are package-level values
// ([ErrIssuerRequired], [ErrKeysetRequired], …), so a caller inspecting
// them uses [errors.Is] rather than constructing anything.
//
// Callers that produce an Error build it as a composite literal. That is
// the path a [CustomGrantHandler] takes to choose its own wire response:
// returning an *Error from Handle makes the OP emit exactly that code and
// description, while returning any other error is mapped to invalid_grant
// with the message redacted. For example:
//
//	return op.CustomGrantResponse{}, &op.Error{
//		Code:        "invalid_grant",
//		Description: "service token is expired",
//		Cause:       err,
//	}
//
// Code is not free-form — see its own documentation for the permitted
// values.
type Error struct {
	// Code is the OAuth-style machine-readable error code. It MUST be
	// one of the RFC 6749 §5.2 codes the OP already emits —
	// "access_denied", "invalid_client", "invalid_grant",
	// "invalid_request", "invalid_scope", "unauthorized_client",
	// "unsupported_grant_type", "unsupported_response_type" — or one of
	// the operator-fault codes "configuration_error", "server_error",
	// "temporarily_unavailable". Ad-hoc codes are forbidden. Nothing
	// rewrites an unrecognised one — [Error.WriteOAuthError] copies
	// Code onto the wire verbatim and falls back to HTTP 400 for its
	// status, so an invented code ships to the client as-is.
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

// OAuthCode returns the receiver's RFC 6749 §5.2 wire code. The
// method exists so internal code paths can recognise a typed [*Error]
// through a structural interface without importing the op package
// (the rule "internal MUST NOT import op" forbids the direct
// reference). Returns the empty string when the receiver is nil so
// callers can guard with a single zero-value check.
//
// Stable since v1.0.
func (e *Error) OAuthCode() string {
	if e == nil {
		return ""
	}
	return e.Code
}

// WriteOAuthError renders the receiver as an RFC 6749 §5.2 wire
// envelope. The method exists so embedder code paths that surface a
// typed [*Error] (a [TokenExchangePolicy] denial, a custom-grant
// handler rejection) can ride through the token endpoint's
// preserve-verbatim seam without re-encoding the value. The HTTP
// status is derived from the code class: 5xx for server / config
// failures, 401 for invalid_client (RFC 6749 §5.2 normative shape),
// 400 for every other client-class code.
//
// Stable since v1.0.
func (e *Error) WriteOAuthError(w http.ResponseWriter) {
	if e == nil {
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatusFor(e.Code))
	body := struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description,omitempty"`
	}{
		Error:            e.Code,
		ErrorDescription: e.Description,
	}
	_ = json.NewEncoder(w).Encode(body)
}

// httpStatusFor maps an OAuth error code onto the HTTP status code
// the wire response carries. The mapping follows RFC 6749 §5.2 and
// matches the rest of the library's error wiring.
func httpStatusFor(code string) int {
	switch code {
	case codeInvalidClient:
		return http.StatusUnauthorized
	case codeServerError, codeTemporarilyUnavailable, codeConfiguration:
		return http.StatusInternalServerError
	default:
		return http.StatusBadRequest
	}
}

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
// Stable since v1.0.
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
// Stable since v1.0.
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

// ErrUserStoreRequired is returned by [New] when [WithUserStore] receives a
// nil store. The option exists to redirect claim reads somewhere specific;
// passing nothing would silently leave them on the [WithStore] backend, which
// is what omitting the option already does.
var ErrUserStoreRequired = &Error{
	Code:        codeConfiguration,
	Description: "WithUserStore requires a non-nil store.UserStore",
}

// ErrIssuerInvalid is returned by [New] when [WithIssuer] receives a value
// that is not a syntactically valid absolute issuer URL, per OpenID Connect
// Discovery 1.0 §3 / FAPI 2.0 §5.4. The value MUST carry a non-empty
// authority, no trailing slash, no query and no fragment, and be in RFC 3986
// canonical form (lowercase scheme and host, canonical path, no default port).
//
// The scheme MUST be https, except that http is admitted for development when
// the host is a loopback IP literal in 127.0.0.0/8 or [::1] — or, once
// [WithAllowLocalhostLoopback] has been supplied, the textual host
// "localhost". The textual host needs the opt-in because its resolution can be
// hijacked (RFC 8252 §7.3) while an IP literal's cannot.
var ErrIssuerInvalid = &Error{
	Code:        codeConfiguration,
	Description: "issuer must be an absolute URL with no trailing slash, query, or fragment (https; http permitted only for loopback IP literals; pass op.WithAllowLocalhostLoopback() to also admit the textual \"localhost\" host)",
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

// ErrCustomGrantNil is returned when [WithCustomGrant] is called with
// a nil [CustomGrantHandler]. The OP rejects nil at construction time
// because a nil dispatcher would silently fall through to the
// unsupported_grant_type response on every request the caller meant
// to handle, masking the misconfiguration.
var ErrCustomGrantNil = &Error{
	Code:        codeConfiguration,
	Description: "WithCustomGrant requires a non-nil CustomGrantHandler",
}

// ErrCustomGrantNameEmpty is returned when [WithCustomGrant] is given
// a handler whose [CustomGrantHandler.Name] returns the empty string.
// An empty grant_type cannot be matched against a request, so the OP
// refuses the registration rather than silently accepting a handler
// that never fires.
var ErrCustomGrantNameEmpty = &Error{
	Code:        codeConfiguration,
	Description: "CustomGrantHandler.Name must return a non-empty grant_type URN",
}

// ErrCustomGrantBuiltinCollision is returned when [WithCustomGrant]
// is given a handler whose [CustomGrantHandler.Name] equals a
// grant_type the OP implements itself. The reserved set is every
// grant_type the token endpoint routes natively — one per constant of
// the grant.Type enumeration — together with each extension grant the
// OP ships a handler for, such as the RFC 8693 token exchange enabled
// by [RegisterTokenExchange]. The set is a property of the library
// rather than of the deployment, so a registration is refused whether
// or not the colliding grant is enabled on this provider.
//
// The OP refuses the override because the handler would take the wire
// away from an implementation carrying invariants it cannot be assumed
// to reproduce: PKCE, refresh-token rotation, and device-code polling
// on the natively routed grants; audience narrowing, scope
// intersection, and sender-constraint re-binding on the extension
// grants.
var ErrCustomGrantBuiltinCollision = &Error{
	Code:        codeConfiguration,
	Description: "CustomGrantHandler.Name collides with a built-in grant_type",
}

// ErrCustomGrantDuplicate is returned when [WithCustomGrant] is
// called twice with the same [CustomGrantHandler.Name]. The OP
// requires unique URNs so the dispatch table has a single owner per
// grant_type; reordering the option calls would otherwise shadow
// earlier registrations silently.
var ErrCustomGrantDuplicate = &Error{
	Code:        codeConfiguration,
	Description: "CustomGrantHandler.Name was already registered by an earlier WithCustomGrant call",
}

// ErrCustomGrantSecretLikeExempt is returned when a registered
// [CustomGrantHandler]'s [ParamPolicy.DupesAllowed] list names a
// security-sensitive parameter (grant_type / client_id /
// client_secret / code / code_verifier / refresh_token /
// subject_token / actor_token / password / client_assertion /
// client_assertion_type). The OP refuses the registration because
// admitting duplicates of a credential parameter would let a
// misconfigured handler ratchet the OP's authentication or
// PKCE / refresh-token surface down to the weakest of the values.
var ErrCustomGrantSecretLikeExempt = &Error{
	Code:        codeConfiguration,
	Description: "ParamPolicy.DupesAllowed names a security-sensitive parameter that cannot be exempted",
}

// ErrTokenExchangePolicyNil is returned when [RegisterTokenExchange]
// is called with a nil [TokenExchangePolicy]. Token-exchange admission
// requires an explicit deny-by-default decision hook; the OP refuses
// the registration so a deployment cannot accidentally enable
// RFC 8693 exchange without naming the policy that gates it.
var ErrTokenExchangePolicyNil = &Error{
	Code:        codeConfiguration,
	Description: "RegisterTokenExchange requires a non-nil TokenExchangePolicy",
}

// ErrTokenExchangeDuplicate is returned when [RegisterTokenExchange]
// is called more than once. Token-exchange has a single canonical
// grant_type URN so a second registration would shadow the first
// silently; the OP refuses the duplicate so the misconfiguration
// surfaces at construction time.
var ErrTokenExchangeDuplicate = &Error{
	Code:        codeConfiguration,
	Description: "RegisterTokenExchange was already invoked on this configuration",
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
