package authorize

import (
	"context"
	"errors"

	"github.com/libraz/go-oidc-provider/internal/authorizationdetails"
	"github.com/libraz/go-oidc-provider/internal/jarm"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Grant Management draft action wire strings that are meaningful on an
// authorization request. The draft's query / revoke actions are operations
// on the grant management endpoint (GET / DELETE) rather than on an
// authorization request, so they are deliberately absent here and are
// rejected by [Request.ValidateExtensions].
const (
	// GrantManagementActionCreate requests a brand-new grant. A grant_id
	// MUST NOT accompany it.
	GrantManagementActionCreate = "create"

	// GrantManagementActionReplace overwrites the referenced grant with
	// the new request's authorization. Requires a grant_id.
	GrantManagementActionReplace = "replace"

	// GrantManagementActionMerge unions the referenced grant with the new
	// request's authorization. Requires a grant_id.
	GrantManagementActionMerge = "merge"
)

// ExtensionPolicy carries the OP-resolved feature state the extension gates
// consult. Like [Policy] it holds resolved bits rather than the profile that
// produced them: the validator does not know about profiles, only about what
// the OP has been configured to honour.
//
// A zero value disables every gate, which is what an OP that registered no
// authorization_details types, left Grant Management off, and did not enable
// DPoP wants.
type ExtensionPolicy struct {
	// AuthorizationDetailTypes is the RFC 9396 registry (accepted "type"
	// → validator). An empty registry means the OP has not opted into
	// RAR and the authorization_details parameter is treated as an
	// unknown extension: ignored, not rejected.
	AuthorizationDetailTypes map[string]authorizationdetails.Validator

	// GrantManagementEnabled gates the Grant Management draft
	// parameters. When false the parameters are cleared off the request
	// as unknown extensions rather than rejected.
	GrantManagementEnabled bool

	// GrantManagementActions is the wire-string-keyed set of actions the
	// OP accepts. Consulted only when GrantManagementEnabled is true.
	GrantManagementActions map[string]bool

	// GrantManagementActionRequired rejects a request that carries no
	// grant_management_action at all. Consulted only when
	// GrantManagementEnabled is true.
	GrantManagementActionRequired bool

	// DPoPEnabled reports whether the OP can honour an RFC 9449 §10.1
	// "dpop_jkt" commitment: bind the issued access token to that key
	// and refuse a redemption that does not prove possession of it. An
	// OP that can do neither must refuse the commitment rather than
	// silently drop it.
	DPoPEnabled bool

	// JARMEnabled reports whether the OP can wrap an authorization
	// response in the JARM signed JWT. False means no signer is wired,
	// so a request that selects one of the four JARM response_mode
	// values ("jwt", "query.jwt", "fragment.jwt", "form_post.jwt") asks
	// for a response shape the OP cannot produce and must be refused.
	JARMEnabled bool

	// JARMResponseModeRequired forces every authorization request to
	// select a JARM response_mode, implementing the FAPI 2.0 Message
	// Signing §5.5 mandate that every authorize response be
	// JARM-wrapped. A request that asks for a plain mode (or omits
	// response_mode and so takes the response_type-implied default) is
	// refused: the shape it asked for is the one the profile forbids.
	// Only meaningful together with JARMEnabled.
	JARMResponseModeRequired bool
}

// ValidateExtensions runs the request gates that sit between a successful
// [Request.Validate] and the endpoint's terminal action: the JARM
// response_mode rules, RFC 9396 authorization_details, the Grant Management
// draft parameters, and the RFC 9449 §10.1 "dpop_jkt" commitment. It
// returns nil when the request is admissible and the rejection to render
// otherwise.
//
// The method decides; it does not render. That split is what lets the
// authorization endpoint and the pushed-authorization-request endpoint share
// one rule set while answering in the two different shapes they owe their
// callers — /authorize redirects the error to a redirect_uri it has already
// validated, /par writes a JSON envelope because there may be no trusted
// redirect target yet. The two endpoints are consecutive gates on the same
// request, so a rule that fires at only one of them strands the RP: /par
// would mint a request_uri that /authorize then refuses, after the one-time
// value has been spent.
//
// Every returned rejection is redirect-safe by construction ([IsRedirectSafe]
// returns true for all of them) because the method runs only after
// [Request.Validate] has matched redirect_uri against the client's
// registration.
//
// The method mutates req: validated authorization_details are stamped onto
// [Request.AuthorizationDetails] for the grant emission path, and the Grant
// Management parameters are cleared when the feature is off. Both endpoints
// depend on that, /par so the persisted snapshot carries the decoded
// elements and /authorize so a snapshot replayed under a since-disabled
// feature cannot smuggle the parameters back in.
//
// ctx is forwarded to the embedder-supplied authorization_details
// validators; the gates themselves perform no I/O.
func (req *Request) ValidateExtensions(ctx context.Context, client *store.Client, policy ExtensionPolicy) *Error {
	// The response-mode gate runs first: it decides whether the OP can
	// deliver any response at all in the shape the request asked for, so
	// it is faulted before the gates that judge what the response would
	// carry.
	if rejection := req.validateJARMResponseMode(policy); rejection != nil {
		return rejection
	}
	if rejection := req.validateAuthorizationDetails(ctx, client, policy); rejection != nil {
		return rejection
	}
	if rejection := req.validateGrantManagement(policy); rejection != nil {
		return rejection
	}
	return req.validateDPoPCommitment(policy)
}

// validateJARMResponseMode reconciles the response_mode the request
// selected with what the OP can and must deliver. [Request.validateResponseMode]
// has already filtered the catalogue of known names; this gate decides
// whether the named mode is usable on this OP.
//
// Two rules, both derived from configuration the request cannot see:
//
//   - The request selected a JARM mode while no signer is wired. The OP
//     would have to answer in a shape it cannot produce.
//   - The active profile requires every response to be JARM-wrapped and
//     the request selected a plain mode (or none, taking the
//     response_type-implied default).
//
// Both surface unsupported_response_mode: the response_mode is the
// parameter at fault either way, and the RP resolves both by picking a
// different one.
//
// The rules read the pushed parameters only — no session, no interaction
// state — so the pushed-authorization-request endpoint reaches the same
// verdict the authorization endpoint will. That is what keeps /par from
// minting a request_uri whose one-time value the RP spends on a request
// the next gate refuses.
func (req *Request) validateJARMResponseMode(policy ExtensionPolicy) *Error {
	requested := jarm.IsJARM(req.ResponseMode)
	if requested && !policy.JARMEnabled {
		return ErrJARMUnsupported
	}
	if !requested && policy.JARMResponseModeRequired {
		return ErrJARMResponseModeRequired
	}
	return nil
}

// validateAuthorizationDetails honours the RFC 9396 authorization_details
// parameter when the OP has registered any types. It decodes and validates
// the raw parameter against the registry and stamps the validated elements
// onto req. When no types are registered the parameter is treated as an
// unknown extension and ignored.
func (req *Request) validateAuthorizationDetails(
	ctx context.Context,
	client *store.Client,
	policy ExtensionPolicy,
) *Error {
	if len(policy.AuthorizationDetailTypes) == 0 || req.AuthorizationDetailsRaw == "" {
		return nil
	}
	details, err := authorizationdetails.Check(ctx, req.AuthorizationDetailsRaw, client, policy.AuthorizationDetailTypes)
	if err != nil {
		// An over-size payload is a malformed request; every other
		// failure is RFC 9396 §5's invalid_authorization_details.
		if errors.Is(err, authorizationdetails.ErrTooLarge) {
			return ErrAuthorizationDetailsTooLarge
		}
		return ErrAuthorizationDetailsInvalid
	}
	req.AuthorizationDetails = details
	return nil
}

// validateGrantManagement enforces the Grant Management draft request rules.
// When the feature is disabled the parameters are ignored (cleared off req)
// as unknown extensions. When enabled it checks the action is one the OP
// accepts and is an authorize-time action, and that grant_id presence matches
// the action (forbidden for create, required for replace / merge).
//
// Ownership of grant_id is deliberately NOT checked here: it is enforced at
// grant emission, where the authenticated subject is known. A pushed request
// has no subject yet, so a check here could only be weaker than the one that
// already runs.
func (req *Request) validateGrantManagement(policy ExtensionPolicy) *Error {
	if !policy.GrantManagementEnabled {
		req.GrantManagementAction = ""
		req.GrantID = ""
		return nil
	}
	action := req.GrantManagementAction
	if action == "" {
		if policy.GrantManagementActionRequired {
			return ErrGrantManagementActionRequired
		}
		return nil
	}
	switch action {
	case GrantManagementActionCreate, GrantManagementActionReplace, GrantManagementActionMerge:
		// authorize-time action; continue.
	default:
		return ErrGrantManagementActionNotAuthorizeTime
	}
	if !policy.GrantManagementActions[action] {
		return ErrGrantManagementActionUnsupported
	}
	if action == GrantManagementActionCreate && req.GrantID != "" {
		return ErrGrantIDForbiddenOnCreate
	}
	if (action == GrantManagementActionReplace || action == GrantManagementActionMerge) && req.GrantID == "" {
		return grantIDRequiredFor(action)
	}
	return nil
}

// validateDPoPCommitment refuses a request that commits to a DPoP key while
// the OP cannot honour the commitment. RFC 9449 §10.1 gives "dpop_jkt"
// exactly one meaning — the token endpoint MUST bind the issued access token
// to that key and MUST refuse a redemption that does not prove possession of
// it — and an OP without DPoP can do neither. Accepting the request anyway
// moves the failure to redemption, where the client learns only that a
// credential it believes is good produced invalid_grant; rejecting here names
// the offending parameter while the client can still do something about it.
//
// Every source the parameter can arrive from is covered, because all of them
// have converged on [Request.DPoPJKT] by this point: the plain wire form, a
// PAR snapshot replayed through a request_uri, and a signed JAR request
// object (RFC 9101 §6.1 merges its claims onto the wire values before
// parsing).
func (req *Request) validateDPoPCommitment(policy ExtensionPolicy) *Error {
	if policy.DPoPEnabled || req.DPoPJKT == "" {
		return nil
	}
	return ErrDPoPJKTUnsupported
}
