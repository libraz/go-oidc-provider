package endsession

import (
	"context"
	"errors"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
)

// sessionFingerprint is the pair the handler reads out of the session
// cookie: the session id to delete and the OP-internal subject whose
// grants the logout cascade retires.
type sessionFingerprint struct {
	sessionID      string
	subject        string
	chooserGroupID string
}

// sessionState classifies what reading the session cookie proved. The
// three values are the only outcomes the logout flow may act on, and
// keeping them apart is a security property rather than a nicety: a
// backend that could not answer says nothing about whether a session
// exists, so folding it onto "there is nothing here" would let a
// storage outage produce a logout that destroys nothing while the
// response, the audit stream and the logout-failure counter all report
// a completed sign-out.
type sessionState uint8

const (
	// sessionStoreUnavailable is the zero value on purpose. A lookup
	// that no branch classified must read as "the store did not answer",
	// because that is the outcome whose mishandling is unsafe; a value
	// nobody set can then never be mistaken for a resolved absence.
	sessionStoreUnavailable sessionState = iota

	// sessionAbsent means the cookie proved there is nothing to
	// terminate: it was missing, it did not decrypt, or it named a
	// session the store has confirmed is gone or expired.
	sessionAbsent

	// sessionActive means the cookie resolved to a live session whose
	// fingerprint is carried alongside.
	sessionActive
)

// sessionLookup is the three-valued result of reading the session
// cookie. The fingerprint travels with its state so every consumer
// decides from the classification rather than from whether the
// fingerprint happens to be empty — the distinction between "resolved
// absent" and "unresolvable" is invisible in the fingerprint alone.
type sessionLookup struct {
	state       sessionState
	fingerprint sessionFingerprint
	// err carries the backend failure behind [sessionStoreUnavailable]
	// so the audit record names the cause. It is nil in every other
	// state.
	err error
}

// admitSessionLookup decides whether the flow may continue past the
// session read. It returns true for the two states that describe the
// session — resolved, or proven absent — and false once it has written
// the response for a session store that could not answer.
//
// The unavailable branch deliberately does all three of the following,
// because dropping any one of them turns an outage into a silent
// no-op:
//
//   - Emits [auditevent.AuditSessionDestroyFailed] (which the metrics
//     bridge projects onto the logout-failure counter), so the outage is
//     visible on the same stream a real deletion failure appears on.
//   - Stops before the CSRF gate. The gate's "nothing to terminate"
//     admission is only sound when the OP knows there is nothing to
//     terminate; an unanswered lookup is not that knowledge, and
//     admitting on it would let a cross-site request skip the
//     confirmation whenever the backend is down.
//   - Stops before the response. The browser must not be told the
//     sign-out completed while the session row and the subject's tokens
//     are still live.
//
// The session cookie is left in place. Clearing it is permitted on
// every path, but here it would cost the only handle the browser has on
// the session that is still running: the user could no longer retry the
// logout the OP just failed to perform.
//
// The switch has no default clause so the exhaustiveness check binds; a
// state added later must state its own policy rather than inheriting a
// permissive one, and the fallthrough return is a refusal either way.
func admitSessionLookup(w http.ResponseWriter, r *http.Request, deps Deps, lookup sessionLookup) bool {
	switch lookup.state {
	case sessionActive, sessionAbsent:
		return true
	case sessionStoreUnavailable:
		emitSessionLookupFailed(r.Context(), deps, lookup)
		writeLogoutError(w, http.StatusServiceUnavailable, descInternalError)
		return false
	}
	return false
}

// emitSessionLookupFailed records that the OP could not read the
// session it was asked to terminate. The event is the same one a failed
// deletion emits: from the outside both mean "a session may still be
// live after a logout request", and an operator watching the
// logout-failure counter needs the read failures in it as much as the
// write failures.
func emitSessionLookupFailed(ctx context.Context, deps Deps, lookup sessionLookup) {
	extras := map[string]any{}
	if lookup.err != nil {
		extras["error"] = lookup.err.Error()
	}
	deps.audit().Emit(ctx, audit.Event{
		Name:    string(auditevent.AuditSessionDestroyFailed),
		Level:   audit.LevelError,
		Message: "session lookup failed; nothing was terminated",
		Extras:  extras,
	})
}

// readSessionLookup classifies the __Host-oidc_session cookie into one
// of the three [sessionState] outcomes and, when a session resolves,
// pulls out the session id and the authenticated subject.
//
// Only two failures are answers about the session: an unusable cookie
// ([sessions.ErrCookieInvalid] — missing, undecryptable, or bound to a
// foreign chooser group) and a session the store confirmed is gone or
// expired ([sessions.ErrCurrentSessionExpired]). Both prove there is
// nothing to terminate. Everything else — a transport failure, a
// timeout, a backend that answered nothing at all — is a fault: the OP
// asked whether a session exists and did not learn the answer, so it
// may not proceed as though the answer were "no".
func readSessionLookup(r *http.Request, deps Deps) sessionLookup {
	c, err := r.Cookie(cookie.SessionProfile.Name)
	if err != nil || c == nil || c.Value == "" {
		return sessionLookup{state: sessionAbsent}
	}
	active, err := deps.Sessions.Resolve(r.Context(), c.Value)
	if err != nil {
		if errors.Is(err, sessions.ErrCookieInvalid) || errors.Is(err, sessions.ErrCurrentSessionExpired) {
			return sessionLookup{state: sessionAbsent}
		}
		return sessionLookup{state: sessionStoreUnavailable, err: err}
	}
	if active == nil || active.Session == nil {
		// The manager folds a missing row into ErrCurrentSessionExpired,
		// so reaching here means it broke its own contract. Treat the
		// silence as a fault: nothing here proves the session is gone.
		return sessionLookup{state: sessionStoreUnavailable, err: errSessionUnanswered}
	}
	return sessionLookup{
		state: sessionActive,
		fingerprint: sessionFingerprint{
			sessionID:      active.Session.ID,
			subject:        active.Session.Subject,
			chooserGroupID: active.Session.ChooserGroupID,
		},
	}
}

// errSessionUnanswered marks the contract violation of a session
// manager that reports neither a session nor an error.
var errSessionUnanswered = errors.New("endsession: session manager returned no session and no error")
