package authorizeendpoint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// terminalAuthorization is the tuple an /authorize exit is about to bind
// an authorization code to. Every field is what the exit resolved, not
// what the request asked for: the point of the type is to let one
// validator compare the two.
type terminalAuthorization struct {
	// Exit names the route this call came in on. It is the only thing an
	// exit says about which rules apply to it: whether the response is
	// served from an authentication established before this attempt is
	// read off the route's spec, not asserted per call.
	Exit exitKind

	// Backing locates the record holding the authentication the response
	// reports. The gate reads it, applies the request's constraints to
	// what it found, and returns it — so the value the caller goes on to
	// stamp is the value that was checked. See [terminalAuthn] for why
	// the exit hands over a locator instead of an auth_time and an acr.
	Backing terminalAuthn

	// Subject is the account the code will be issued for. On the
	// interactive exit this is the subject the credential chain bound,
	// which is not necessarily the subject the request arrived with.
	Subject string

	// Scope is the scope set the code will carry.
	Scope []string

	// ConsentAnswered reports that a consent ceremony returned a scope
	// decision during this attempt. An answered ceremony is authoritative
	// for the subject it ran under, whatever it decided.
	ConsentAnswered bool

	// ConsentFromCachedGrant reports that no consent ceremony ran because
	// a grant found at the door already covered the request. The lookup
	// used the subject the request arrived with, so it only stands if the
	// exit binds that same subject.
	ConsentFromCachedGrant bool

	// Grant is the durable grant the code will hang off, when the exit
	// resolved it before validating. Nil on exits that create or amend
	// the grant afterwards; the consent re-check then reads the terminal
	// subject's grant itself.
	Grant *store.Grant
}

// errTerminalSubjectMissing signals that an exit reached the code-issuing
// gate without a subject to bind the code to.
var errTerminalSubjectMissing = errors.New("authorizeendpoint: terminal authorization has no subject")

// errTerminalExitUnknown signals that a call reached the code-issuing
// gate without naming which route it came in on, or naming one the gate
// has no rules for. The rules are not guessable from the rest of the
// input, so the gate refuses rather than picking a default.
var errTerminalExitUnknown = errors.New("authorizeendpoint: terminal authorization names no exit")

// errTerminalAuthnUnavailable signals that an exit named a route but
// supplied nothing to read the backing authentication from. Serving the
// response would mean reporting an authentication nobody sourced.
var errTerminalAuthnUnavailable = errors.New("authorizeendpoint: terminal authorization has no authentication source")

// errTerminalGrantMismatch signals that the grant an exit resolved does
// not describe the authorization the request asked for: a different
// principal, a scope the grant does not hold, or a claims projection
// other than this request's. It is an internal inconsistency rather than
// a client error, so callers surface it as server_error.
var errTerminalGrantMismatch = errors.New("authorizeendpoint: terminal grant does not match the request")

// errTerminalConsentUncovered signals that the scope the exit is about to
// grant is not backed by consent from the subject the exit bound.
var errTerminalConsentUncovered = errors.New("authorizeendpoint: terminal subject has not consented to the requested scope")

// errACRUnmet signals that the authentication backing the response
// cannot satisfy the authentication context the request required — the
// configured ACR policy refused an acr the request marked essential, or
// the session an account chooser bound does not satisfy the requested
// acr. The caller translates it into the
// unmet_authentication_requirements wire error; flattening the acr to
// "" instead (the treatment a voluntary request gets) would hand the
// relying party a code for an authentication it declared insufficient.
var errACRUnmet = errors.New("authorizeendpoint: essential acr is not satisfied")

// errStaleAuthentication signals that the authentication bound to the
// response is older than the request's max_age, or that the request
// asked for a fresh one with prompt=login. The caller translates it
// into login_required, which is the same error the dispatcher emits
// when the entry session fails the identical check — an RP that uses
// max_age as a step-up gate sees one outcome regardless of which
// account the user picked.
var errStaleAuthentication = errors.New("authorizeendpoint: authentication is older than max_age")

// validateTerminalAuthorization is the single gate every /authorize exit
// that emits an authorization code passes through, immediately before
// the code is persisted.
//
// The routes into it are enumerated by [exitKind], and each of them
// arrives with its own reason for believing the request may be served.
// Those reasons were all formed at the door, against the session the
// request arrived with and the grant that session's subject held at that
// moment. Between the door and the code, the credential chain may bind a
// different subject, an account chooser may bind a different session,
// and a concurrent request may amend the grant. The invariants are
// therefore re-established here, against what the exit actually
// resolved:
//
//   - the exit names a route the gate has rules for;
//   - a subject is bound;
//   - the grant the code hangs off belongs to that subject and this
//     client, holds the scope the code will carry, and records this
//     request's claims projection;
//   - the authentication backing the response — read here, off the
//     record the exit pointed at — satisfies the request's max_age /
//     prompt=login freshness and its acr_values;
//   - the scope being granted is backed by consent from the bound
//     subject.
//
// It returns the authentication it resolved so the caller stamps the
// value that passed rather than reading the record a second time.
// Callers map the returned sentinel onto their own channel: the
// interaction path terminates the ceremony, the silent path answers the
// redirect, and both refuse to mint.
func validateTerminalAuthorization(
	ctx context.Context,
	deps resolved,
	req *authorize.Request,
	in terminalAuthorization,
) (grantAuthContext, error) {
	if !in.Exit.valid() {
		return grantAuthContext{}, errTerminalExitUnknown
	}
	if req == nil || in.Subject == "" {
		return grantAuthContext{}, errTerminalSubjectMissing
	}
	if err := validateTerminalGrant(deps, req, in); err != nil {
		return grantAuthContext{}, err
	}
	authCtx, err := resolveTerminalAuthentication(ctx, deps, req, in, deps.now().UTC())
	if err != nil {
		return grantAuthContext{}, err
	}
	if err := validateTerminalConsent(ctx, deps, req, in); err != nil {
		return grantAuthContext{}, err
	}
	return authCtx, nil
}

// validateTerminalGrant checks the grant the exit resolved against the
// request. Exits that have not resolved one yet pass: the grant they go
// on to write is built from the very request being validated, so there
// is nothing for the two to disagree about.
func validateTerminalGrant(deps resolved, req *authorize.Request, in terminalAuthorization) error {
	g := in.Grant
	if g == nil {
		return nil
	}
	if g.ID == "" || g.Subject != in.Subject || g.ClientID != req.ClientID {
		return errTerminalGrantMismatch
	}
	if !oidcscope.Subset(in.Scope, g.Scope) {
		return errTerminalGrantMismatch
	}
	if !terminalClaimsCurrent(deps, req, g) {
		return errTerminalGrantMismatch
	}
	return nil
}

// terminalClaimsCurrent reports whether the grant records *this*
// request's OIDC Core 1.0 §5.5 claims payload.
//
// The code carries its own request's payload, which is what the token and
// userinfo endpoints project; the grant's copy is what they fall back to
// for a code or token written without one, so it is kept current with
// the latest request. A nil payload is not a mismatch: "absent" leaves
// the grant's payload in place, matching the upsert path's rule that a
// nil payload does not erase the grant's claims.
func terminalClaimsCurrent(deps resolved, req *authorize.Request, g *store.Grant) bool {
	if !deps.ClaimsParameterEnabled {
		return true
	}
	encoded := authorize.EncodeClaimsToGrant(req.Claims)
	if encoded == nil {
		return true
	}
	return claimsPayloadEqual(g.Claims, encoded)
}

// claimsPayloadEqual compares two [store.Grant.Claims] payloads through
// their JSON encoding rather than structurally.
//
// A grant read back from a store that serialises records returns the
// payload as generic JSON — every number a float64, whatever the request
// parser produced — so a structural comparison would report a difference
// that no consumer of the projection can observe. Marshalling both sides
// removes the representation from the comparison; Go emits object keys
// in sorted order, so the encoding is canonical for equal payloads.
func claimsPayloadEqual(stored, requested map[string]any) bool {
	rawStored, err := json.Marshal(stored)
	if err != nil {
		return false
	}
	rawRequested, err := json.Marshal(requested)
	if err != nil {
		return false
	}
	return bytes.Equal(rawStored, rawRequested)
}

// resolveTerminalAuthentication reads the authentication backing the
// response off the record that holds it, then re-applies the request's
// freshness and authentication-context constraints to what it found.
//
// The constraints apply only to a response served from an authentication
// established before this attempt — the routes [exitSpec] marks
// ServesEstablishedSession. A ceremony that ran during the attempt
// satisfies prompt=login and max_age by construction, and its acr is the
// ACR resolution seam's verdict.
//
// The read happens here rather than at the caller so the exit cannot
// hand the gate an assurance of its own composition, and the resolved
// value is returned so the two never diverge downstream.
func resolveTerminalAuthentication(
	ctx context.Context,
	deps resolved,
	req *authorize.Request,
	in terminalAuthorization,
	now time.Time,
) (grantAuthContext, error) {
	if in.Backing == nil {
		return grantAuthContext{}, errTerminalAuthnUnavailable
	}
	authCtx, err := in.Backing.authContext(ctx)
	if err != nil {
		return grantAuthContext{}, err
	}
	if !in.Exit.spec().ServesEstablishedSession {
		return authCtx, nil
	}
	if err := sessionMayServe(ctx, deps, req, authCtx.entry(in.Subject), now); err != nil {
		return grantAuthContext{}, err
	}
	return authCtx, nil
}

// sessionMayServe applies the request's prompt=login, max_age and
// acr constraints to an established session's authentication entry.
// The door, the chooser pick and the terminal gate all ask it, so the
// three readings cannot drift. It returns [errStaleAuthentication] or
// [errACRUnmet], staleness first.
func sessionMayServe(
	ctx context.Context,
	deps resolved,
	req *authorize.Request,
	entry authn.EntryAuthn,
	now time.Time,
) error {
	if slices.Contains(req.Prompt, interaction.PromptLogin) {
		return errStaleAuthentication
	}
	if req.MaxAge != nil && authorize.AuthenticationIsStale(entry.AuthTime, now, *req.MaxAge) {
		return errStaleAuthentication
	}
	if acrUnsatisfiedByRequest(ctx, deps, entry, req) {
		return errACRUnmet
	}
	return nil
}

// validateTerminalConsent re-evaluates the consent decision against the
// subject the exit bound.
//
// The decision that suppressed the consent screen was taken at the door,
// from a grant looked up against the subject the session cookie carried
// at the time. Every branch that re-runs authentication — prompt=login,
// an expired max_age, an RFC 9470 step-up — can bind a different subject
// at the credential screen, and the account chooser can bind one
// outright; carrying the first subject's consent over to the second
// would hand it a code for a scope set it never saw. The coverage
// predicate is therefore re-run here against the terminal subject's own
// grant, and a subject with no covering grant fails closed.
//
// Two exits skip the re-check, for the same reason in both cases: the
// decision was not made from a cached grant. An answered ceremony is
// authoritative for the subject it ran under, and a chain that was never
// pre-marked keeps whatever consent policy the embedder's own
// interactions implement.
func validateTerminalConsent(
	ctx context.Context,
	deps resolved,
	req *authorize.Request,
	in terminalAuthorization,
) error {
	if in.ConsentAnswered || !in.ConsentFromCachedGrant {
		return nil
	}
	grant := in.Grant
	if grant == nil {
		if deps.Grants == nil {
			return errTerminalConsentUncovered
		}
		found, err := findGrantForConsentDecision(ctx, deps.Grants, in.Subject, req.ClientID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return errTerminalConsentUncovered
			}
			return err
		}
		grant = found
	}
	if !consentAlreadyCovered(req, grant) {
		return errTerminalConsentUncovered
	}
	return nil
}

// acrSatisfiedBySession reports whether the established session entry
// satisfies any of the requested acr values. RFC 9470 step-up: when no
// requested context is satisfied, the OP re-authenticates rather than
// silently reuse the weaker session.
//
// The judgement is the configured [op.ACRPolicy]'s, through
// [Deps.ACRSatisfier]: the session's canonical acr gives its level, and
// the policy's own ladder decides which requested values that level
// reaches. The policy that picks the acr a response reports is the one
// that decides whether the session may serve it, so the two cannot
// disagree. A nil satisfier keeps exact membership of the session's acr,
// where an empty acr satisfies nothing.
func acrSatisfiedBySession(ctx context.Context, deps resolved, entry authn.EntryAuthn, requested []string) bool {
	for _, want := range requested {
		if deps.ACRSatisfier != nil {
			if deps.ACRSatisfier(ctx, want, entry) {
				return true
			}
			continue
		}
		if entry.ACR != "" && entry.ACR == want {
			return true
		}
	}
	return false
}

// acrUnsatisfiedByRequest reports whether entry fails the request's
// acr_values or its essential acr claim.
func acrUnsatisfiedByRequest(ctx context.Context, deps resolved, entry authn.EntryAuthn, req *authorize.Request) bool {
	if req == nil {
		return false
	}
	if len(req.ACRValues) > 0 && !acrSatisfiedBySession(ctx, deps, entry, req.ACRValues) {
		return true
	}
	spec, ok := req.Claims.IDTokenSpec("acr")
	if !ok || !spec.Essential {
		return false
	}
	if len(spec.Values) == 0 && spec.Value == nil {
		return entry.ACR == ""
	}
	var wanted []string
	if value, ok := spec.Value.(string); ok {
		wanted = append(wanted, value)
	}
	for _, candidate := range spec.Values {
		if value, ok := candidate.(string); ok {
			wanted = append(wanted, value)
		}
	}
	return !acrSatisfiedBySession(ctx, deps, entry, wanted)
}

// terminalRefusal renders a terminal-validation sentinel as the wire
// code, description, and whether the condition is permanent (the record
// is retired) or transient (the record survives for a retry).
func terminalRefusal(err error) (code, description string, permanent bool) {
	switch {
	case errors.Is(err, errACRUnmet):
		return errUnmetAuthenticationRequirements,
			"the authentication performed does not satisfy the requested acr", true
	case errors.Is(err, errStaleAuthentication):
		return errLoginRequired,
			"the selected account's authentication is older than max_age", true
	case errors.Is(err, errChooserSubjectMismatch):
		return errAccessDenied,
			"the selected account no longer matches the authenticated subject", true
	case errors.Is(err, errSessionAuthnUnavailable):
		return errLoginRequired,
			"the session backing this authorization is no longer available", true
	case errors.Is(err, errTerminalSubjectMissing):
		return errAccessDenied, "subject was not authenticated", true
	case errors.Is(err, errTerminalConsentUncovered):
		return errAccessDenied,
			"the authenticated account has not consented to the requested scope", true
	case errors.Is(err, errTerminalGrantMismatch):
		return errServerError, "the authorization grant does not match the request", false
	default:
		return errServerError, "could not resolve authentication context", false
	}
}
