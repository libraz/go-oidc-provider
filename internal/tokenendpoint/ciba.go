package tokenendpoint

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/ciba"
	cgrant "github.com/libraz/go-oidc-provider/internal/grants/ciba"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/internal/tokens"
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
		writeError(w, http.StatusBadRequest, errUnsupportedGrantType,
			"grant_type is not supported")
		return
	}
	dpopOut, ok := verifyTokenDPoP(w, r, deps)
	if !ok {
		return
	}
	client, _, ok := authenticate(ctx, w, r, deps)
	if !ok {
		return
	}
	in, ok := parseCIBARequest(w, r)
	if !ok {
		return
	}
	mtlsOut, ok := verifyTokenMTLS(w, r, deps, dpopOut.JKT)
	if !ok {
		return
	}
	binding := tokenBinding{
		DPoPJKT:        dpopOut.JKT,
		MTLSThumbprint: mtlsOut.Thumbprint,
	}
	if !enforceSenderConstraint(w, deps, binding) {
		return
	}
	rec, ok := lookupCIBARequest(ctx, w, deps, in.AuthReqID, client.ID)
	if !ok {
		return
	}
	if !applyCIBAPollDecision(ctx, w, deps, rec, in.AuthReqID, client.ID) {
		return
	}
	authorized, ok := authorizeCIBAPoll(w, deps, client, rec, binding)
	if !ok {
		emitCIBAReject(ctx, deps, client.ID, errInvalidGrant)
		return
	}
	consumed, ok := consumeCIBARequest(ctx, w, deps, in.AuthReqID)
	if !ok {
		return
	}
	issueCIBAResponse(ctx, w, deps, client, consumed, authorized, binding)
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
		writeError(w, http.StatusBadRequest, errInvalidRequest, "auth_req_id is required")
		return cibaInputs{}, false
	}
	return in, true
}

// applyCIBAPollDecision computes the polling decision per CIBA
// Core §11 and short-circuits the wire response on every non-emit
// branch. The helper also stamps the LastPolledAt observation
// (for the next slow_down ladder step), persists the doubled
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
	// Stamp the poll timestamp and any slow_down interval escalation before
	// branching so the next poll's ladder sees the current observation. A
	// store fault here is non-fatal: the worst case is the next poll gets
	// the same decision because LastPolledAt or Interval is stale, which is
	// the correct fail-open behaviour for a transient substore outage. We
	// surface the fault as a warn-level audit event so SOC tooling can spot
	// a transient outage that quietly defeats the slow_down ladder; the
	// poll decision itself still proceeds because RecordPoll is best-effort
	// observability rather than a single-use gate.
	nextInterval := rec.Interval
	if decision.Decision == ciba.PollDecisionSlowDown {
		nextInterval = decision.NextInterval
	}
	if err := deps.CIBARequests.RecordPoll(ctx, authReqID, now, nextInterval); err != nil {
		deps.audit().Emit(ctx, audit.Event{
			Name:     ciba.AuditPollObservationFailed,
			Level:    audit.LevelWarn,
			Message:  "ciba poll observation persistence failed; slow_down ladder may read stale LastPolledAt",
			ClientID: clientID,
			Extras: map[string]any{
				"error": err.Error(),
			},
		})
	}
	switch decision.Decision {
	case ciba.PollDecisionAuthorizationPending:
		emitCIBAReject(ctx, deps, clientID, errAuthorizationPending)
		writeError(w, http.StatusBadRequest, errAuthorizationPending,
			"authorization request is still pending")
		return false
	case ciba.PollDecisionSlowDown:
		emitCIBASlowDown(ctx, deps, clientID, rec.Interval, decision.NextInterval)
		strikes, err := deps.CIBARequests.IncrementPollViolation(ctx, authReqID)
		threshold := deps.CIBAMaxPollViolations
		if threshold == 0 {
			threshold = ciba.MaxPollViolations
		}
		if err == nil && strikes >= threshold {
			if denyErr := deps.CIBARequests.Deny(ctx, authReqID, "poll_abuse"); denyErr == nil {
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
		}
		writeError(w, http.StatusBadRequest, errSlowDown,
			"polling interval has been increased; back off and retry")
		return false
	case ciba.PollDecisionAccessDenied:
		emitCIBAReject(ctx, deps, clientID, errAccessDenied)
		writeError(w, http.StatusBadRequest, errAccessDenied,
			"authorization request was denied")
		return false
	case ciba.PollDecisionExpiredToken:
		emitCIBAReject(ctx, deps, clientID, errExpiredToken)
		writeError(w, http.StatusBadRequest, errExpiredToken,
			"auth_req_id expired")
		return false
	case ciba.PollDecisionAlreadyRedeemed:
		// CIBA Core §11 reserves expired_token for TTL elapse only;
		// auth_req_id replay maps to invalid_grant per RFC 6749
		// §5.2. OFCS' fapi-ciba CIBA-11 assertion pins this wire
		// distinction.
		emitCIBAReject(ctx, deps, clientID, errInvalidGrant)
		writeError(w, http.StatusBadRequest, errInvalidGrant,
			"auth_req_id was already redeemed")
		return false
	case ciba.PollDecisionEmit:
		return true
	case ciba.PollDecisionInvalid:
		fallthrough
	default:
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return false
	}
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
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			emitCIBARejectWithExtras(ctx, deps, clientID, errExpiredToken, map[string]any{
				"lookup": "not_found",
			})
			writeError(w, http.StatusBadRequest, errExpiredToken,
				"auth_req_id expired or already consumed")
			return nil, false
		}
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return nil, false
	}
	if rec.ClientID != clientID {
		emitCIBAReject(ctx, deps, clientID, errInvalidGrant)
		writeError(w, http.StatusBadRequest, errInvalidGrant, "auth_req_id rejected")
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
) (*cgrant.Authorized, bool) {
	authorized, err := cgrant.Authorize(cgrant.AuthorizeInput{
		Client:                client,
		Record:                rec,
		PresentedDPoPJKT:      binding.DPoPJKT,
		PresentedMTLSCertS256: binding.MTLSThumbprint,
	})
	if err != nil {
		writeCIBAAuthError(w, err)
		return nil, false
	}
	if !checkTokenScopeAllowlist(w, deps, client.ID, authorized.Scope) {
		return nil, false
	}
	return authorized, true
}

// writeCIBAAuthError translates the [cgrant.Err*] sentinels onto
// wire codes. The mapping mirrors the comments on the package
// sentinels (internal/grants/ciba/ciba.go):
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
//   - default                  → server_error (programmer bug).
func writeCIBAAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, cgrant.ErrGrantNotPermitted):
		writeError(w, http.StatusBadRequest, errUnauthorizedClient,
			"client is not authorized for the ciba grant")
	case errors.Is(err, cgrant.ErrScopeForbidden):
		writeError(w, http.StatusBadRequest, errInvalidScope,
			"granted scope exceeds the client's registered set")
	case errors.Is(err, cgrant.ErrCnfBindingMismatch),
		errors.Is(err, cgrant.ErrCnfBindingMissing):
		writeError(w, http.StatusBadRequest, errInvalidGrant,
			"sender-constraint binding does not match the bc-authorize record")
	case errors.Is(err, cgrant.ErrPendingApproval):
		writeError(w, http.StatusBadRequest, errAuthorizationPending,
			"authorization request is still pending")
	case errors.Is(err, cgrant.ErrDenied):
		writeError(w, http.StatusBadRequest, errAccessDenied,
			"authorization request was denied")
	case errors.Is(err, cgrant.ErrExpired):
		writeError(w, http.StatusBadRequest, errExpiredToken,
			"auth_req_id expired")
	case errors.Is(err, cgrant.ErrAlreadyRedeemed):
		writeError(w, http.StatusBadRequest, errInvalidGrant,
			"auth_req_id was already redeemed")
	default:
		writeError(w, http.StatusInternalServerError, errServerError, "")
	}
}

// consumeCIBARequest atomically transitions the record from
// Approved to Consumed and returns the consumed snapshot. The
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
) (*store.CIBARequest, bool) {
	consumed, err := deps.CIBARequests.Consume(ctx, authReqID)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrAlreadyConsumed):
			writeError(w, http.StatusBadRequest, errInvalidGrant,
				"auth_req_id was already redeemed")
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusBadRequest, errExpiredToken,
				"auth_req_id expired or unknown")
		case errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusBadRequest, errInvalidGrant,
				"auth_req_id is not in a consumable state")
		default:
			writeError(w, http.StatusInternalServerError, errServerError, "")
		}
		return nil, false
	}
	return consumed, true
}

// issueCIBAResponse mints the access token, optionally an
// id_token (only when scope contains openid), and optionally a
// refresh token (only when [clientPermitsRefresh] AND the granted
// scope satisfies the OIDC Core 1.0 §11 / per-client refresh gate).
// The function reuses [mintAccessToken] / [maybeIssueRefreshToken]
// so the cnf-claim plumbing, opaque-format dispatch, and audit
// emission all stay aligned with the authorization_code path.
//
// audience selection: the /bc-authorize endpoint rejects
// multi-resource requests with invalid_target, so
// [authorized.Audience] holds at most one canonicalised entry. The
// handler reads index 0 (or empty when none was registered),
// matching the access-token aud claim's single-entry encoding.
//
// acr / amr threading: the bc-authorize record carries requested
// ACR values for the authentication device, but token issuance stamps
// only the ACR that the device actually satisfied at Approve time.
// amr is left unset until the substore retains a real authentication-
// method signal.
func issueCIBAResponse(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	consumed *store.CIBARequest,
	authorized *cgrant.Authorized,
	binding tokenBinding,
) {
	now := deps.now().UTC()
	resource := ""
	if len(authorized.Audience) > 0 {
		resource = authorized.Audience[0]
	}
	// auth_time is the wall-clock at which the end user completed the
	// authentication-device interaction —
	// store.CIBARequestStore.Approve stamps it onto the record. A
	// zero value means the substore did not retain an auth_time
	// (legacy records persisted before the column was introduced);
	// the encoder omits the claim in that case, matching OIDC Core
	// 1.0 §2's "OPTIONAL unless the client requires it" posture.
	// Clients that set RequireAuthTime block id_token issuance via
	// requireAuthTimeForIDToken below when the value is zero.
	if err := requireAuthTimeForIDToken(client, authorized.Scope, authTimeUnix(authorized.AuthTime)); err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "required auth_time is unavailable")
		return
	}
	authTime := authTimeUnix(authorized.AuthTime)
	publicSubject, err := projectPublicSubject(ctx, deps, authorized.Subject, client)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	accessToken, err := mintAccessToken(
		ctx,
		deps,
		authorized.Subject,
		publicSubject,
		client.ID,
		consumed.ID,
		authorized.Scope,
		resource,
		now,
		authTime,
		binding,
		nil,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	var idToken string
	if oidcscope.ContainsOpenID(authorized.Scope) {
		idToken, err = mintCIBAIDToken(deps, cibaIDTokenInput{
			Subject:     publicSubject,
			ClientID:    client.ID,
			AccessToken: accessToken,
			Now:         now,
			AuthTime:    authTime,
			ACR:         authorized.ACR,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, errServerError, "")
			return
		}
		idToken, err = maybeEncryptIDToken(ctx, deps, client, idToken)
		if err != nil {
			writeError(w, http.StatusInternalServerError, errServerError, "")
			return
		}
	}
	refreshToken, err := maybeIssueRefreshToken(
		ctx,
		deps,
		client,
		authorized.Subject,
		consumed.ID,
		authorized.Scope,
		resource,
		"",
		binding,
		store.RefreshOriginCIBA,
		false,
		authContext{
			AuthTime: authTime,
			ACR:      authorized.ACR,
		},
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	emitCIBAIssued(ctx, deps, cibaIssuedExtras{
		ClientID:         client.ID,
		Subject:          authorized.Subject,
		Scope:            authorized.Scope,
		Audience:         authorized.Audience,
		SenderConstraint: authorized.SenderConstraint,
	})
	writeSuccess(w, successResponse{
		AccessToken:  accessToken,
		TokenType:    binding.tokenTypeFor(),
		ExpiresIn:    int64(deps.AccessTokenTTL.Seconds()),
		RefreshToken: refreshToken,
		IDToken:      idToken,
		Scope:        joinScope(authorized.Scope),
	})
}

// cibaIDTokenInput collects the parameters [mintCIBAIDToken]
// needs. The struct exists so the function stays under the
// project's parameter-count cap; CIBA poll mode does not have a
// code for c_hash and does not preserve a nonce across the
// authentication-device interaction (the embedder MAY surface
// one, but the v0.9.x substore does not retain it), so those
// fields are absent.
type cibaIDTokenInput struct {
	Subject     string
	ClientID    string
	AccessToken string
	Now         time.Time
	AuthTime    int64
	ACR         string
}

// mintCIBAIDToken signs the id_token issued in response to a
// CIBA poll redemption. at_hash is populated per OIDC Core
// §3.1.3.6 because the access token is bound to the same
// redemption and matches the spec's "ID Token issued from a
// Token Endpoint" shape. c_hash is omitted because CIBA has no
// authorization code to bind. nonce is omitted because the
// v0.9.x substore does not retain one. auth_time is populated
// when the substore stamped a non-zero value at Approve time;
// the encoder omits the claim on zero.
func mintCIBAIDToken(deps Deps, in cibaIDTokenInput) (string, error) {
	key := activeSigningKey(deps)
	atHash, err := tokens.HashForAlg(in.AccessToken, key.Alg)
	if err != nil {
		return "", err
	}
	claims := tokens.IDTokenClaims{
		Issuer:    deps.Issuer,
		Subject:   in.Subject,
		Audience:  []string{in.ClientID},
		IssuedAt:  in.Now.Unix(),
		ExpiresAt: tokens.ExpiresIn(in.Now, deps.IDTokenTTL),
		AtHash:    atHash,
		AuthTime:  in.AuthTime,
	}
	claims.ACR = in.ACR
	return tokens.SignIDToken(key, claims)
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
// rejection event so SOC tooling can see the doubling ladder
// without parsing the audit name. effective is the bar before
// doubling; next is the elevated bar.
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
