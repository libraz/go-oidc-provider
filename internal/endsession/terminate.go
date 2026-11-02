package endsession

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/backchannel"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/revocation"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// terminateSessionForScope performs the destructive part of /end_session.
// It is the success-path side effect: delete the session
// record the cookie pointed at, hand a back-channel logout fan-out to
// the affected RPs off to the coordinator, and clear the cookie in the
// response. Downstream revocation and back-channel failures are
// deliberately non-blocking for the browser response, but they are
// recorded as distinct audit events rather than being misreported as a
// successful session destruction. A failure to delete the session rows
// themselves is returned to the caller: the browser must not be told the
// sign-out completed while the session it names is still usable.
//
// The ordering here is load-bearing. Session deletion and the
// access-token cascade run on the request path, so the response is
// never written while the session the user asked to end is still live.
// Back-channel delivery does not: it is an out-of-band exchange with
// the relying parties, bounded only by how fast the slowest of them
// answers, so it is detached and the caller proceeds to write the
// response.
//
// lookup is the classified session read [serve] performed before the
// CSRF gate ran, so the session that gets destroyed is exactly the one
// the gate authorised.
//
// The all-scope branch snapshots the chooser group before deleting anything;
// the snapshot is the source of truth for both the revocation and BCL
// cascades. The current-scope branch removes only the active row and lets the
// session manager rebind the cookie to a surviving sibling.
//
// It returns a non-nil error when the OP could not confirm that every
// session row in the requested scope is gone. On that path the session
// cookie is left untouched, so the browser keeps the one handle it has
// for retrying, and the caller MUST NOT report success.
//
// The state switch is a backstop rather than the primary gate — [serve]
// answers an unavailable store before the flow reaches here — but it is
// what makes the destructive path safe for any future caller: it cannot
// be handed a lookup that never resolved a session and treat the
// resulting empty fingerprint as an idempotent no-op.
//
//nolint:gocognit,cyclop // The destructive workflow keeps failure audit, revocation, and cookie ordering explicit.
func terminateSessionForScope(w http.ResponseWriter, r *http.Request, deps Deps, lookup sessionLookup, scope string) error {
	ctx := r.Context()
	if scope == "" {
		scope = logoutScopeAll
	}

	switch lookup.state {
	case sessionAbsent:
		cookie.ClearOn(w, cookie.SessionProfile)
		return nil
	case sessionStoreUnavailable:
		// No session was ever resolved, so there is nothing this
		// function could delete. Record the fault instead of returning
		// as though the logout had nothing to do.
		emitSessionLookupFailed(ctx, deps, lookup)
		return errSessionNotDestroyed
	case sessionActive:
		// Fall through to the destructive workflow.
	}

	sess := lookup.fingerprint
	if sess.sessionID == "" {
		cookie.ClearOn(w, cookie.SessionProfile)
		return nil
	}

	snapshot := make([]*store.Session, 0, 1)
	var sessionErr error
	var removal sessions.Removal
	switch scope {
	case logoutScopeCurrent:
		// The session fingerprint was resolved immediately before the CSRF
		// gate. Preserve it even when the row disappears during the gate so
		// token and BCL cascades still describe the operation the user
		// confirmed.
		snapshot = append(snapshot, &store.Session{
			ID:             sess.sessionID,
			Subject:        sess.subject,
			ChooserGroupID: sess.chooserGroupID,
		})
		if sess.chooserGroupID == "" {
			sessionErr = deps.Sessions.Logout(ctx, sess.sessionID)
		} else {
			removal, sessionErr = deps.Sessions.Remove(ctx, sess.chooserGroupID, sess.sessionID, sess.sessionID)
		}
	default:
		if sess.chooserGroupID == "" {
			sessionErr = errors.New("endsession: active session has no chooser group")
		} else {
			var err error
			snapshot, err = deps.Sessions.SnapshotGroup(ctx, sess.chooserGroupID)
			if err != nil {
				sessionErr = err
				// Keep the active row in the cascade and make one best-effort
				// deletion attempt. A failed snapshot cannot safely be claimed
				// as group-wide success, but leaving the active row untouched is
				// worse for the browser that explicitly confirmed logout.
				snapshot = append(snapshot, &store.Session{
					ID:             sess.sessionID,
					Subject:        sess.subject,
					ChooserGroupID: sess.chooserGroupID,
				})
				if logoutErr := deps.Sessions.Logout(ctx, sess.sessionID); logoutErr != nil && !errors.Is(logoutErr, store.ErrNotFound) {
					sessionErr = errors.Join(sessionErr, logoutErr)
				}
			} else {
				sessionErr = deps.Sessions.LogoutAllSnapshot(ctx, snapshot)
			}
		}
	}
	if scope != logoutScopeCurrent && len(snapshot) == 0 && sessionErr == nil {
		// The active cookie was valid when the request entered the flow,
		// but the chooser group was already empty by the time the
		// destructive snapshot ran. Treat this as an idempotent logout
		// outcome and retain the explicit audit distinction from a live
		// row that failed to delete.
		deps.audit().Emit(ctx, audit.Event{
			Name:      string(auditevent.AuditSessionAlreadyAbsent),
			Level:     audit.LevelInfo,
			Message:   "session was already absent",
			ActorID:   sess.subject,
			SessionID: sess.sessionID,
		})
	}

	for _, row := range snapshot {
		if row == nil || row.ID == "" {
			continue
		}
		if sessionErr == nil {
			deps.audit().Emit(ctx, audit.Event{
				Name:      string(auditevent.AuditSessionDestroyed),
				Level:     audit.LevelInfo,
				Message:   "session destroyed",
				ActorID:   row.Subject,
				SessionID: row.ID,
			})
		} else {
			deps.audit().Emit(ctx, audit.Event{
				Name:      string(auditevent.AuditSessionDestroyFailed),
				Level:     audit.LevelError,
				Message:   "session logout persistence failed",
				ActorID:   row.Subject,
				SessionID: row.ID,
				Extras:    map[string]any{"error": sessionErr.Error()},
			})
		}
	}

	if err := revokeAccessTokensForSnapshot(ctx, deps, snapshot); err != nil {
		deps.audit().Emit(ctx, audit.Event{
			Name:    string(auditevent.AuditLogoutTokenRevokeFailed),
			Level:   audit.LevelError,
			Message: "logout token revocation failed",
			Extras:  map[string]any{"error": err.Error()},
		})
	}
	notifyBackchannelForSnapshot(ctx, deps, snapshot)

	if sessionErr != nil {
		// At least one session row survived the request. Leave the cookie
		// alone: it is the browser's only handle on the session that is
		// still running, and clearing it would cost the user the ability
		// to retry the logout the OP just failed to perform.
		return sessionErr
	}
	if scope == logoutScopeCurrent && removal.Cookie != "" && len(removal.Remaining) > 0 {
		if err := cookie.SetSession(w, removal.Cookie, removal.ExpiresAt, timex.OrSystem(deps.Clock).Now().UTC()); err == nil {
			return nil
		}
	}
	cookie.ClearOn(w, cookie.SessionProfile)
	return nil
}

// notifyBackchannelForSnapshot hands one back-channel logout fan-out to
// the coordinator per distinct subject in the pre-delete snapshot.
//
// The unit of a back-channel logout token is the subject, not the browser
// session: this OP deliberately issues subject-only logout tokens (no
// sid), so N browser sessions of one account in a chooser group would
// otherwise produce N semantically identical fan-outs. Each RP would
// receive N tokens differing only in jti, and the coordinator's inflight
// budget would be spent N times over — under load that sheds fan-outs
// that other subjects still needed. The sibling token cascade dedupes on
// the same key for the same reason.
//
// The Notice still carries the session id of the first row seen for the
// subject, so an operator correlating the audit stream has a handle on
// the ceremony that produced the fan-out.
func notifyBackchannelForSnapshot(ctx context.Context, deps Deps, snapshot []*store.Session) {
	if deps.Backchannel == nil {
		return
	}
	hasID := func(row *store.Session) bool { return row.ID != "" }
	for _, row := range distinctSubjects(snapshot, hasID) {
		deps.Backchannel.NotifyDetached(ctx, backchannel.Notice{
			Subject:   row.Subject,
			SessionID: row.ID,
		})
	}
}

// revokeAccessTokens cascades RP-Initiated Logout to the access-token
// substores: every grant the subject currently holds is retired so
// subsequent /userinfo, /introspection, and resource-server validations
// reject the outstanding bearer tokens immediately rather than waiting
// for their exp claim to elapse.
//
// The JWT branch dispatches on [Deps.RevocationStrategy]:
//
//   - [store.RevocationStrategyGrantTombstone] (default): write a
//     [store.GrantTombstone] row per grant. Tokens issued before
//     `RevokedAt` are rejected on next verify; future issuances under
//     the same grant are refused at the token endpoint.
//   - [store.RevocationStrategyJTIRegistry]: flip every shadow row
//     under the grant via [store.AccessTokenRegistry.RevokeByGrant]
//     (the per-JTI path).
//   - [store.RevocationStrategyNone]: skip the JWT cascade; the
//     embedder accepted the RFC 6749 §4.1.2 wiggle.
//
// The opaque branch ([Deps.OpaqueAccessTokens]) runs independently
// for every strategy when the substore is wired — opaque tokens have
// their own per-token state and the JWT-strategy switch does not
// apply to them.
//
// A nil [Deps.Grants] short-circuits both branches — the embedder
// has not opted into the registry surface. The caller keeps logout
// user-visible-successful, but receives any store errors to emit an accurate
// audit event.
//
// Each grant is torn down through [revocation.Revoker], the same dispatch
// /revoke and grant management use, so the JWT / opaque / refresh rungs
// and the tombstone-retention formula cannot drift between the three
// endpoints.
func revokeAccessTokens(ctx context.Context, deps Deps, subject string) error {
	if deps.Grants == nil {
		return nil
	}
	grants, err := deps.Grants.ListBySubject(ctx, subject)
	if err != nil {
		return fmt.Errorf("list grants: %w", err)
	}
	revoker := revocation.NewRevoker(
		deps.RefreshTokens, deps.OpaqueAccessTokens, deps.AccessTokens, deps.GrantRevocations,
		deps.RevocationStrategy, deps.AccessTokenTTL, timex.OrSystem(deps.Clock).Now().UTC(), "logout",
	)
	var errs []error
	for _, g := range grants {
		if g == nil || g.ID == "" {
			continue
		}
		out := revoker.Run(ctx, revocation.WholeGrant(g.ID))
		for _, f := range out.Failures {
			errs = append(errs, fmt.Errorf("grant %s %s: %w", g.ID, f.Surface, f.Err))
		}
	}
	return errors.Join(errs...)
}

// revokeAccessTokensForSnapshot runs the token cascade once per distinct
// subject represented by the pre-delete session snapshot. A chooser group
// can contain several browser sessions for the same subject; repeating the
// grant and refresh-token walks would be both wasteful and capable of turning
// an otherwise harmless idempotent logout into a backend error storm.
func revokeAccessTokensForSnapshot(ctx context.Context, deps Deps, snapshot []*store.Session) error {
	var errs []error
	for _, row := range distinctSubjects(snapshot, nil) {
		if err := revokeAccessTokens(ctx, deps, row.Subject); err != nil {
			errs = append(errs, fmt.Errorf("subject %s: %w", row.Subject, err))
		}
	}
	return errors.Join(errs...)
}

// errSessionNotDestroyed reports that the destructive workflow could not
// establish that the requested sessions are gone. It stands in for the
// unreadable-store case, where no per-row deletion error exists but the
// OP equally cannot claim the sign-out happened.
var errSessionNotDestroyed = errors.New("endsession: session termination could not be confirmed")

// distinctSubjects returns the first snapshot row per non-empty subject,
// ignoring nil rows and rows keep rejects. keep may be nil.
func distinctSubjects(snapshot []*store.Session, keep func(*store.Session) bool) []*store.Session {
	seen := make(map[string]struct{}, len(snapshot))
	out := make([]*store.Session, 0, len(snapshot))
	for _, row := range snapshot {
		if row == nil || row.Subject == "" || (keep != nil && !keep(row)) {
			continue
		}
		if _, ok := seen[row.Subject]; ok {
			continue
		}
		seen[row.Subject] = struct{}{}
		out = append(out, row)
	}
	return out
}
