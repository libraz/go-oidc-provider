package authorizeendpoint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// terminalAuthorization is the tuple an /authorize exit is about to bind
// an authorization code to. Every field is what the exit resolved, not
// what the request asked for: the point of the type is to let one
// validator compare the two.
type terminalAuthorization struct {
	// Subject is the account the code will be issued for. On the
	// interactive exit this is the subject the credential chain bound,
	// which is not necessarily the subject the request arrived with.
	Subject string

	// Scope is the scope set the code will carry.
	Scope []string

	// AuthTime and ACR describe the authentication backing the response:
	// the ceremony that just ran, the session the account chooser bound,
	// or the session a silent mint is served from.
	AuthTime time.Time
	ACR      string

	// SessionBacked reports that the authentication above was established
	// before this attempt rather than during it. The request's freshness
	// and authentication-context constraints were evaluated at the door
	// against the session the *cookie* carried, which is not necessarily
	// this one, so they are re-applied here. A ceremony that ran during
	// this attempt is instead governed by the ACR resolution seam, which
	// has already had its say by the time this validator runs.
	SessionBacked bool

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
// the session an account chooser bound carries an acr outside the
// requested set. The caller translates it into the
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
// The endpoint has four such exits — a silent mint against a cached
// grant, a first-party auto-grant, a completed interaction, and the
// resumption of one — and each of them arrives with its own reason for
// believing the request may be served. Those reasons were all formed at
// the door, against the session the request arrived with and the grant
// that session's subject held at that moment. Between the door and the
// code, the credential chain may bind a different subject, an account
// chooser may bind a different session, and a concurrent request may
// amend the grant. The invariants are therefore re-established here,
// against what the exit actually resolved:
//
//   - a subject is bound;
//   - the grant the code hangs off belongs to that subject and this
//     client, holds the scope the code will carry, and records this
//     request's claims projection;
//   - the authentication backing the response satisfies the request's
//     max_age / prompt=login freshness and its acr_values;
//   - the scope being granted is backed by consent from the bound
//     subject.
//
// Callers map the returned sentinel onto their own channel: the
// interaction path terminates the ceremony, the silent path answers the
// redirect, and both refuse to mint.
func validateTerminalAuthorization(
	ctx context.Context,
	deps resolved,
	req *authorize.Request,
	in terminalAuthorization,
) error {
	if req == nil || in.Subject == "" {
		return errTerminalSubjectMissing
	}
	if err := validateTerminalGrant(deps, req, in); err != nil {
		return err
	}
	if err := validateTerminalAuthentication(req, in, deps.now().UTC()); err != nil {
		return err
	}
	return validateTerminalConsent(ctx, deps, req, in)
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
	if !scopeIsSubset(in.Scope, g.Scope) {
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
// The token and userinfo endpoints read the projection off the grant, so
// a code that hangs off a grant carrying an older request's payload
// answers with the older projection and reports nothing about it. A nil
// payload is not a mismatch: "absent" leaves whatever the subject
// previously agreed to in place, matching the upsert path's rule that a
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

// validateTerminalAuthentication re-applies the request's freshness and
// authentication-context constraints to the authentication that actually
// backs the response.
//
// It runs only for a response served from an authentication established
// before this attempt. A ceremony that ran during the attempt satisfies
// prompt=login and max_age by construction, and its acr is the ACR
// resolution seam's verdict — re-deriving one here from string
// membership would overrule the configured [op.ACRPolicy].
func validateTerminalAuthentication(req *authorize.Request, in terminalAuthorization, now time.Time) error {
	if !in.SessionBacked {
		return nil
	}
	if containsString(req.Prompt, interaction.PromptLogin) {
		return errStaleAuthentication
	}
	if req.MaxAge != nil && authorize.AuthenticationIsStale(in.AuthTime, now, *req.MaxAge) {
		return errStaleAuthentication
	}
	if acrUnsatisfiedByRequest(in.ACR, req) {
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
