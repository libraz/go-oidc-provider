package tokenendpoint

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	cgrant "github.com/libraz/go-oidc-provider/internal/grants/ciba"
	"github.com/libraz/go-oidc-provider/internal/grants/pollgrant"
	"github.com/libraz/go-oidc-provider/internal/pollinterval"
	"github.com/libraz/go-oidc-provider/op/store"
)

// handleCIBA implements the
// "grant_type=urn:openid:params:grant-type:ciba" branch of OIDC
// CIBA Core 1.0 §11. The orchestration mirrors the device-code
// handler: client authentication, DPoP / mTLS verification,
// record lookup, polling discipline, the CIBA authorization
// gates, atomic record consume, and credential mint. The flow
// short-circuits on every gate so a poll the OP refuses never
// advances state on the substore.
//
// The persistence boundary lives entirely inside this function:
// the substore mutates exactly twice per successful poll
// (RecordPoll for the slow_down ladder and Consume for the
// single-use guarantee), and no token write coordinates a
// transaction with the CIBA row (the substore is intentionally
// outside the transactional cluster because the approve→consume
// CAS already provides single-use; see the godoc on
// [store.CIBARequestStore]).
func handleCIBA(w http.ResponseWriter, r *http.Request, deps Deps) {
	ctx := r.Context()
	if deps.CIBARequests == nil {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errUnsupportedGrantType,
			"grant_type is not supported")
		return
	}
	// Proof verification, client authentication, and the proof's
	// replay marking run in the order [authenticateWithDPoP] documents.
	dpopOut, client, ok := authenticateWithDPoP(ctx, w, r, deps, grantTypeCIBA)
	if !ok {
		return
	}
	in, ok := parseCIBARequest(w, r)
	if !ok {
		return
	}
	binding, _, ok := bindRequest(w, r, deps, client, dpopOut)
	if !ok {
		return
	}
	rec, ok := lookupCIBARequest(ctx, w, deps, in.AuthReqID, client.ID)
	if !ok {
		return
	}
	if !applyCIBAPollDecision(ctx, w, deps, rec, in.AuthReqID, client.ID) {
		return
	}
	authorized, reason, ok := authorizeCIBAPoll(w, deps, client, rec, binding)
	if !ok {
		emitCIBAReject(ctx, deps, client.ID, reason)
		return
	}
	user, err := lookupLiveSubject(ctx, deps, authorized.Subject)
	if err != nil {
		if errors.Is(err, errSubjectDeprovisioned) {
			retireDeprovisionedCIBARequest(ctx, deps, client.ID, authorized.Subject, in.AuthReqID)
		}
		writeSubjectLookupError(w, err)
		return
	}
	issued, err := preparePolledResponse(ctx, deps, client, polledRedemption{
		Subject:  authorized.Subject,
		Scope:    authorized.Scope,
		Audience: authorized.Audience,
		AuthTime: authorized.AuthTime,
		ACR:      authorized.ACR,
	}, user, binding, polledIssuance{
		Origin:                store.RefreshOriginCIBA,
		DiscardGrantOnFailure: true,
	})
	if err != nil {
		endpointsupport.WriteServerError(w)
		return
	}
	if !consumeCIBARequest(ctx, w, deps, in.AuthReqID) {
		issued.cleanup(ctx, deps)
		return
	}
	// A RevokeSubject that listed the grant while the credentials were being
	// persisted could not retire what was written after it; refuse here.
	if !refuseIssuanceUnderClosedGrant(ctx, w, deps, issued.issuedUnder(rec.IssuedAt), "auth_req_id rejected") {
		return
	}
	emitCIBAIssued(ctx, deps, cibaIssuedExtras{
		ClientID:         client.ID,
		Subject:          authorized.Subject,
		Scope:            authorized.Scope,
		Audience:         authorized.Audience,
		SenderConstraint: authorized.SenderConstraint,
	})
	writeSuccess(w, issued.response)
}

// cibaInputs is the de-structured view of the form parameters the
// handler consumes for the CIBA grant.
type cibaInputs struct {
	AuthReqID string
}

// parseCIBARequest validates the required form fields. CIBA Core
// §11 names auth_req_id as the only required parameter; the
// grant_type / client authentication parameters are validated by
// the shared dispatcher.
func parseCIBARequest(w http.ResponseWriter, r *http.Request) (cibaInputs, bool) {
	in := cibaInputs{AuthReqID: r.PostForm.Get("auth_req_id")}
	if in.AuthReqID == "" {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest, "auth_req_id is required")
		return cibaInputs{}, false
	}
	return in, true
}

// applyCIBAPollDecision computes the polling decision per CIBA
// Core §11 and short-circuits the wire response on every non-emit
// branch. The helper also stamps the LastPolledAt observation
// (for the next slow_down ladder step), persists the raised
// interval on slow_down via [store.CIBARequestStore.RecordPoll], and triggers
// the poll-abuse lockout when the strike counter saturates. It
// returns true when the decision is "emit" — the only branch that
// lets the caller proceed to authorization gates and credential
// issuance.
func applyCIBAPollDecision(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	rec *store.CIBARequest,
	authReqID, clientID string,
) bool {
	now := deps.now().UTC()
	decision := ciba.DecidePoll(ciba.PollInput{
		Now:               now,
		LastPolledAt:      derefTime(rec.LastPolledAt),
		EffectiveInterval: rec.Interval,
		ExpiresAt:         rec.ExpiresAt,
		Approved:          rec.Status == store.CIBARequestStatusApproved,
		Denied:            rec.Status == store.CIBARequestStatusDenied,
		Consumed:          rec.Status == store.CIBARequestStatusConsumed,
		PollViolations:    rec.PollViolations,
		MaxPollViolations: deps.CIBAMaxPollViolations,
	})
	spec := pollSpec{
		observationFailedEvent:   ciba.AuditPollObservationFailed,
		observationFailedMessage: "ciba poll observation persistence failed; slow_down ladder may read stale LastPolledAt",
		recordPoll: func(ctx context.Context, at time.Time, interval time.Duration) error {
			return deps.CIBARequests.RecordPoll(ctx, authReqID, at, interval)
		},
		reject: func(ctx context.Context, code string) { emitCIBAReject(ctx, deps, clientID, code) },
		slowDown: func(ctx context.Context, d pollinterval.Output) {
			emitCIBASlowDown(ctx, deps, clientID, rec.Interval, d.NextInterval)
			recordCIBAPollViolation(ctx, deps, authReqID, clientID)
		},
		expiredDescription:  "auth_req_id expired",
		redeemedDescription: "auth_req_id was already redeemed",
	}
	return applyPollOutcome(ctx, w, deps, spec, decision, now, rec.Interval, clientID)
}

// recordCIBAPollViolation counts a slow_down strike against the request and
// denies it, with an audit event, once the configured threshold is reached.
func recordCIBAPollViolation(ctx context.Context, deps Deps, authReqID, clientID string) {
	strikes, err := deps.CIBARequests.IncrementPollViolation(ctx, authReqID)
	threshold := deps.CIBAMaxPollViolations
	if threshold == 0 {
		threshold = ciba.MaxPollViolations
	}
	if err != nil || strikes < threshold {
		return
	}
	if denyErr := deps.CIBARequests.Deny(ctx, authReqID, "poll_abuse"); denyErr != nil {
		return
	}
	deps.audit().Emit(ctx, audit.Event{
		Name:     ciba.AuditPollAbuseLockout,
		Level:    audit.LevelWarn,
		Message:  "ciba record locked: poll-violation count exceeded",
		ClientID: clientID,
		Extras: map[string]any{
			"strikes":     int(strikes),
			"max_strikes": int(threshold),
		},
	})
}

// lookupCIBARequest resolves the polling record from the substore
// and enforces the client_id binding. A missing record collapses
// to expired_token per CIBA Core §11; a client mismatch collapses
// to invalid_grant so an attacker cannot probe for a known
// auth_req_id across client identities.
func lookupCIBARequest(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	authReqID, clientID string,
) (*store.CIBARequest, bool) {
	rec, err := deps.CIBARequests.FindByAuthReqID(ctx, authReqID)
	if err == nil && rec == nil {
		// A nil record alongside a nil error violates the store contract;
		// an auth_req_id the backend cannot produce is treated as unknown.
		err = store.ErrNotFound
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			emitCIBARejectWithExtras(ctx, deps, clientID, errExpiredToken, map[string]any{
				"lookup": "not_found",
			})
			endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errExpiredToken,
				"auth_req_id expired or already consumed")
			return nil, false
		}
		endpointsupport.WriteServerError(w)
		return nil, false
	}
	if rec.ClientID != clientID {
		emitCIBAReject(ctx, deps, clientID, errInvalidGrant)
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidGrant, "auth_req_id rejected")
		return nil, false
	}
	return rec, true
}

// authorizeCIBAPoll wraps [cgrant.Authorize] and maps its
// sentinels onto wire codes. The function returns the authorised
// projection on success or writes the wire response and returns
// (nil, false) on rejection.
func authorizeCIBAPoll(
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	rec *store.CIBARequest,
	binding tokenBinding,
) (*cgrant.Authorized, string, bool) {
	authorized, err := cgrant.Authorize(cgrant.AuthorizeInput{
		Client:                client,
		Record:                rec,
		PresentedDPoPJKT:      binding.DPoPJKT,
		PresentedMTLSCertS256: binding.MTLSThumbprint,
	})
	if err != nil {
		code, status, description := cibaAuthError(err)
		endpointsupport.WriteOAuthError(w, status, code, description)
		return nil, code, false
	}
	if !checkTokenScopeAllowlist(w, deps, client.ID, authorized.Scope) {
		return nil, errInvalidScope, false
	}
	return authorized, "", true
}

// cibaAuthError translates the cgrant.Err* sentinels onto the wire code,
// HTTP status and description. The mapping mirrors the comments on the
// package sentinels (internal/grants/ciba/ciba.go):
//
//   - ErrGrantNotPermitted     → unauthorized_client.
//   - ErrScopeForbidden        → invalid_scope.
//   - ErrCnfBindingMismatch /
//     ErrCnfBindingMissing     → invalid_grant.
//   - ErrPendingApproval       → authorization_pending (defensive;
//     [DecidePoll] should have caught this case already).
//   - ErrDenied                → access_denied (same defensive note).
//   - ErrExpired               → expired_token (CIBA Core §11; TTL).
//   - ErrAlreadyRedeemed       → invalid_grant (RFC 6749 §5.2; replay).
//   - ErrSubjectMissing        → invalid_grant (OIDC Core 1.0 §2; the
//     approval names no end user, so no credential can be minted).
//   - default                  → server_error (programmer bug).
func cibaAuthError(err error) (code string, status int, description string) {
	switch {
	case errors.Is(err, cgrant.ErrExpired):
		return errExpiredToken, http.StatusBadRequest, "auth_req_id expired"
	case errors.Is(err, cgrant.ErrAlreadyRedeemed):
		return errInvalidGrant, http.StatusBadRequest, "auth_req_id was already redeemed"
	}
	return pollAuthError(err, pollAuthMap{
		Errors: pollgrant.Errors{
			NotPermitted:   cgrant.ErrGrantNotPermitted,
			SubjectMissing: cgrant.ErrSubjectMissing,
			CnfMissing:     cgrant.ErrCnfBindingMissing,
			CnfMismatch:    cgrant.ErrCnfBindingMismatch,
			ScopeForbidden: cgrant.ErrScopeForbidden,
		},
		Pending:   cgrant.ErrPendingApproval,
		Denied:    cgrant.ErrDenied,
		Grant:     "ciba",
		CnfRecord: "bc-authorize",
		NoSubject: "authorization request is not associated with an end user",
	})
}

// retireDeprovisionedCIBARequest spends an approval whose subject no
// longer exists and records the refusal. The grant is allocated only at
// redemption, so no credential exists yet to tear down. A Consume fault
// is dropped: the approval then lapses on its TTL, and every poll until
// then meets the same subject lookup.
func retireDeprovisionedCIBARequest(ctx context.Context, deps Deps, clientID, subject, authReqID string) {
	_, _ = deps.CIBARequests.Consume(ctx, authReqID)
	emitCIBAReject(ctx, deps, clientID, errInvalidGrant)
	retireDeprovisionedGrant(ctx, deps, deprovisionedRedemption{
		ClientID:  clientID,
		Subject:   subject,
		GrantType: grantTypeCIBA,
	})
}

// consumeCIBARequest atomically transitions the record from
// Approved to Consumed. The
// substore separates two failure modes the wire codes care about:
//
//   - [store.ErrAlreadyConsumed] is the replay path (the record
//     exists but a prior poll already consumed it); RFC 6749 §5.2
//     reserves invalid_grant for any reuse of an issued grant, and
//     OFCS' fapi-ciba CIBA-11 assertion expects exactly that wire
//     code on auth_req_id reuse.
//   - [store.ErrNotFound] covers TTL elapse and unknown auth_req_id
//     uniformly; CIBA Core §11 reserves expired_token for that.
func consumeCIBARequest(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	authReqID string,
) bool {
	consumed, err := deps.CIBARequests.Consume(ctx, authReqID)
	if err == nil && consumed == nil {
		// A nil record alongside a nil error violates the store contract;
		// without the consumed record there is nothing to issue against.
		err = store.ErrNotFound
	}
	if err != nil {
		switch {
		case errors.Is(err, store.ErrAlreadyConsumed):
			endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidGrant,
				"auth_req_id was already redeemed")
		case errors.Is(err, store.ErrNotFound):
			endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errExpiredToken,
				"auth_req_id expired or unknown")
		case errors.Is(err, store.ErrConflict):
			endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidGrant,
				"auth_req_id is not in a consumable state")
		default:
			endpointsupport.WriteServerError(w)
		}
		return false
	}
	return true
}

// cibaIssuedExtras bundles the audit extras the issuance path
// emits. Splitting into a struct keeps [emitCIBAIssued]'s
// signature well under the project's parameter-count cap.
type cibaIssuedExtras struct {
	ClientID         string
	Subject          string
	Scope            []string
	Audience         []string
	SenderConstraint string
}

// emitCIBAIssued logs a successful CIBA poll redemption. The
// audit name matches [ciba.AuditTokenIssued].
func emitCIBAIssued(ctx context.Context, deps Deps, in cibaIssuedExtras) {
	deps.audit().Emit(ctx, audit.Event{
		Name:     ciba.AuditTokenIssued,
		Level:    audit.LevelInfo,
		Message:  "auth_req_id redeemed for tokens",
		ActorID:  in.Subject,
		ClientID: in.ClientID,
		Extras: map[string]any{
			"client_id":         in.ClientID,
			"subject":           in.Subject,
			"scope":             append([]string(nil), in.Scope...),
			"audience":          append([]string(nil), in.Audience...),
			"sender_constraint": in.SenderConstraint,
		},
	})
}

// emitCIBAReject logs a rejected poll. The audit name matches
// [ciba.AuditTokenRejected]; reason is the wire error string the
// OP returned ("authorization_pending", "slow_down",
// "access_denied", "expired_token", or "invalid_grant").
func emitCIBAReject(ctx context.Context, deps Deps, clientID, reason string) {
	emitCIBARejectWithExtras(ctx, deps, clientID, reason, nil)
}

func emitCIBARejectWithExtras(ctx context.Context, deps Deps, clientID, reason string, extras map[string]any) {
	if extras == nil {
		extras = make(map[string]any, 1)
	}
	extras["reason"] = reason
	deps.audit().Emit(ctx, audit.Event{
		Name:     ciba.AuditTokenRejected,
		Level:    audit.LevelInfo,
		Message:  "auth_req_id poll rejected",
		ClientID: clientID,
		Extras:   extras,
	})
}

// emitCIBASlowDown logs a slow_down rejection alongside the
// rejection event so SOC tooling can see the ladder step
// without parsing the audit name. effective is the bar the poll was
// measured against; next is the raised bar.
func emitCIBASlowDown(ctx context.Context, deps Deps, clientID string, effective, next time.Duration) {
	deps.audit().Emit(ctx, audit.Event{
		Name:     ciba.AuditTokenSlowDown,
		Level:    audit.LevelWarn,
		Message:  "auth_req_id poll triggered slow_down",
		ClientID: clientID,
		Extras: map[string]any{
			"effective_interval": effective.String(),
			"next_interval":      next.String(),
		},
	})
}
