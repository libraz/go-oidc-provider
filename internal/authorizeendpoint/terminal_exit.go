package authorizeendpoint

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/store"
)

// exitKind enumerates every route by which /authorize reaches the
// code-issuing gate.
//
// The routes differ in one respect the gate has to know about: whether
// the authentication the response reports was established before this
// attempt or during it. That fact used to travel as a boolean the caller
// set alongside the auth_time and acr it had read for itself, which left
// the gate comparing the request against the exit's own account of the
// authentication. Naming the routes makes "which rules apply" a property
// of a closed set instead of a combination of predicates each caller
// assembles: a route added here without a spec below has no rules, and
// one added without a row in the invariant matrix fails its test.
type exitKind uint8

const (
	// exitUnset is the zero value and never names a route. An exit that
	// did not say which one it is is refused, rather than served under
	// whichever neighbouring route the zero value happened to land on.
	exitUnset exitKind = iota

	// exitSilentCachedGrant answers with no ceremony at all: the session
	// the request arrived with is live, and a grant already covers the
	// requested scope.
	exitSilentCachedGrant

	// exitFirstPartyAutoGrant answers with no ceremony for a first-party
	// client whose consent the OP records on the subject's behalf. No
	// grant covered the request on arrival; one is written as part of the
	// mint.
	exitFirstPartyAutoGrant

	// exitInteractiveChain completes a ceremony in which at least one
	// authenticator ran. The authentication being reported is the one
	// that just happened, and its acr is the ACR resolution seam's
	// verdict over the factors.
	exitInteractiveChain

	// exitInteractiveChooserSession completes a ceremony that
	// authenticated nobody and is served from the session an account
	// chooser bound. That session is not necessarily the one the request
	// arrived with, so nothing the dispatcher checked at the door was
	// checked against it.
	exitInteractiveChooserSession

	// exitInteractiveEntrySession completes a ceremony that authenticated
	// nobody and ran only interactions — an incremental-consent screen
	// against a live session, say — so it is served from the session the
	// request arrived with.
	exitInteractiveEntrySession

	// exitCount bounds the enumeration. It is the length of exitSpecs and
	// of the invariant matrix the tests drive, so a kind declared above
	// it without a spec is a zero-valued row rather than a silent gap.
	exitCount
)

// exitSpec is everything the terminal gate knows about one route.
type exitSpec struct {
	// Name identifies the route in errors and test output.
	Name string

	// ServesEstablishedSession reports that the authentication backing
	// the response was established before this attempt rather than during
	// it.
	//
	// It decides whether the request's freshness and
	// authentication-context constraints are re-applied at the gate. They
	// were evaluated at the door against the session the cookie carried,
	// which for two of these routes is not the session the response ends
	// up being served from. A route that ran a credential chain satisfies
	// prompt=login and max_age by construction, and its acr belongs to
	// the ACR resolution seam, which has already had its say by the time
	// the gate runs.
	ServesEstablishedSession bool
}

// exitSpecs is the whole rule set, one row per route.
//
//nolint:gochecknoglobals // closed enumeration; declared once and treated as a constant lookup table.
var exitSpecs = [exitCount]exitSpec{
	exitUnset:                     {Name: "unset"},
	exitSilentCachedGrant:         {Name: "silent-cached-grant", ServesEstablishedSession: true},
	exitFirstPartyAutoGrant:       {Name: "first-party-auto-grant", ServesEstablishedSession: true},
	exitInteractiveChain:          {Name: "interactive-credential-chain"},
	exitInteractiveChooserSession: {Name: "interactive-chooser-session", ServesEstablishedSession: true},
	exitInteractiveEntrySession:   {Name: "interactive-entry-session", ServesEstablishedSession: true},
}

// valid reports whether k names a route the gate will serve.
func (k exitKind) valid() bool { return k > exitUnset && k < exitCount }

// spec returns the route's rules. It is only meaningful for a k that
// [exitKind.valid] admits; the gate refuses anything else before asking.
func (k exitKind) spec() exitSpec {
	if k >= exitCount {
		return exitSpec{}
	}
	return exitSpecs[k]
}

func (k exitKind) String() string {
	if k >= exitCount {
		return fmt.Sprintf("exitKind(%d)", uint8(k))
	}
	return exitSpecs[k].Name
}

// terminalAuthn resolves the authentication a response reports, from the
// record that holds it.
//
// Exits hand the gate one of these instead of an auth_time and an acr
// they read for themselves. An exit that reports its own assurance is
// both the party asserting the authentication and the party the
// freshness and acr_values checks exist to constrain, so those checks can
// only ever confirm what the exit already believed. Handing over a
// locator moves the read to the checking side, and the gate returns what
// it resolved so the caller stamps the value that was validated rather
// than a second reading of its own.
type terminalAuthn interface {
	// authContext reads the authentication off the record.
	authContext(ctx context.Context) (grantAuthContext, error)
}

// activeSessionAuthn projects the session record the dispatcher already
// resolved for this request.
//
// The record travels rather than the projection: the exit chooses which
// session the gate reads, not what auth_time or acr it sees there. A
// re-read from the store would buy nothing — the silent mint runs inside
// a transaction opened after the dispatcher's read, and reading again
// would measure the request against a session it was never served from.
type activeSessionAuthn struct{ active *sessions.Active }

func (a activeSessionAuthn) authContext(context.Context) (grantAuthContext, error) {
	if a.active == nil || a.active.Session == nil {
		return grantAuthContext{}, errSessionAuthnUnavailable
	}
	return sessionAuthContext(a.active), nil
}

// chooserSessionAuthn reads the session an account chooser bound, named
// on the chain state rather than carried by the cookie.
//
// The subject check is part of the read: a session that has since been
// signed out and replaced under the same chooser group can belong to
// somebody else, and the gate must not describe that person's
// authentication in a code issued for this one.
type chooserSessionAuthn struct {
	deps      resolved
	groupID   string
	sessionID string
	subject   string
}

func (c chooserSessionAuthn) authContext(ctx context.Context) (grantAuthContext, error) {
	authCtx, err := c.deps.Sessions.AuthContext(ctx, c.groupID, c.sessionID)
	if err != nil {
		return grantAuthContext{}, fmt.Errorf(
			"authorizeendpoint: resolve chooser authentication context: %w", err,
		)
	}
	if authCtx.Subject != c.subject {
		return grantAuthContext{}, errChooserSubjectMismatch
	}
	return grantAuthContext{AuthTime: authCtx.AuthTime, ACR: authCtx.ACR, AMR: authCtx.AMR}, nil
}

// errChooserSubjectMismatch signals that the session an account chooser
// bound no longer belongs to the subject the completed chain reports.
// The condition is permanent — the grant a code would hang off can never
// come to match a session owned by somebody else — so the caller retires
// the interaction record and its ceremony cookies instead of leaving a
// completed chain on disk for the user to replay into the same failure.
var errChooserSubjectMismatch = errors.New("authorizeendpoint: chooser authentication context subject mismatch")

// entrySessionAuthn re-reads the browser session the completing request
// carries, for a ceremony that authenticated nobody and is therefore
// served from that session.
type entrySessionAuthn struct {
	r       *http.Request
	deps    resolved
	subject string
}

func (e entrySessionAuthn) authContext(context.Context) (grantAuthContext, error) {
	return currentSessionAuthContext(e.r, e.deps, e.subject)
}

// chainAuthn resolves the authentication a ceremony produced during this
// attempt: [authn.Aggregate] over the factors that ran, then the
// configured ACR policy's verdict over that aggregate.
//
// authTime is the ceremony's own reading; the policy does not move it.
type chainAuthn struct {
	r        *http.Request
	deps     resolved
	rec      *store.Interaction
	req      *authorize.Request
	state    authn.State
	subject  string
	authTime time.Time
}

func (c chainAuthn) authContext(ctx context.Context) (grantAuthContext, error) {
	acr, amr, level := authn.Aggregate(c.state.Factors)
	if c.deps.ACRResolver == nil {
		return grantAuthContext{AuthTime: c.authTime, ACR: acr, AMR: amr}, nil
	}
	out := c.deps.ACRResolver(ctx, ACRResolveInput{
		RequestedACRValues: requestedACRValues(c.req),
		CompletedKinds:     append([]string(nil), c.state.CompletedStepKinds...),
		InternalAAL:        level,
		Subject:            c.subject,
		ClientID:           c.rec.ClientID,
		RequestedScopes:    append([]string(nil), c.req.Scope...),
		RemoteIP:           acrRemoteIP(c.r, c.deps, c.state),
		UserAgent:          acrUserAgent(c.r, c.state),
		AcceptLanguage:     c.r.Header.Get("Accept-Language"),
	})
	switch {
	case out.OK:
		acr = out.ACR
		if out.AMR != nil {
			amr = append([]string(nil), out.AMR...)
		}
	case essentialACRRequested(c.req):
		// A voluntary acr_values request is served with the acr claim
		// omitted when the policy cannot satisfy it; an essential one is
		// refused, because flattening it to "" would hand the relying
		// party a code for an authentication it declared insufficient.
		return grantAuthContext{}, errACRUnmet
	default:
		acr = ""
	}
	return grantAuthContext{AuthTime: c.authTime, ACR: acr, AMR: amr}, nil
}

// interactionExit names the route a completed ceremony took and the
// record whose authentication the response reports.
//
// A chain that ran no authenticator has no authentication of its own to
// describe: [authn.Aggregate] over an empty factor set yields
// acr=""/amr=nil, and the attempt's reference clock is the moment the
// interaction record was created rather than the moment anybody
// authenticated. Both such routes therefore read a session — the one the
// account chooser picked, or the one the request arrived with — so the
// grant never silently downgrades to no-acr / no-amr and the reported
// auth_time keeps naming the authentication that actually happened. Only
// a chain that authenticated somebody reaches the configured ACR
// resolver.
//
//nolint:ireturn // the return is the point: the route names which record the gate reads, and the reader stays unexported.
func interactionExit(
	r *http.Request,
	deps resolved,
	rec *store.Interaction,
	req *authorize.Request,
	st authn.State,
	subject string,
	authTime time.Time,
) (exitKind, terminalAuthn) {
	switch {
	case !noCredentialChainRan(st):
		return exitInteractiveChain, chainAuthn{
			r:        r,
			deps:     deps,
			rec:      rec,
			req:      req,
			state:    st,
			subject:  subject,
			authTime: authTime,
		}
	case chooserReentryBound(st):
		return exitInteractiveChooserSession, chooserSessionAuthn{
			deps:      deps,
			groupID:   st.ChooserGroupID,
			sessionID: st.ChooserSelectedSessionID,
			subject:   subject,
		}
	default:
		return exitInteractiveEntrySession, entrySessionAuthn{r: r, deps: deps, subject: subject}
	}
}

// silentExit names the route a no-ceremony mint took. The two differ in
// where the consent behind the response came from — a grant that already
// existed, or one the OP is writing now on a first-party client's behalf
// — which is what the gate's consent re-check turns on.
//
//nolint:ireturn // as interactionExit: the caller receives a locator, never a concrete reader it could substitute.
func silentExit(hint authorizeHint, active *sessions.Active) (exitKind, terminalAuthn) {
	kind := exitSilentCachedGrant
	if hint.autoGrant != nil {
		kind = exitFirstPartyAutoGrant
	}
	return kind, activeSessionAuthn{active: active}
}
