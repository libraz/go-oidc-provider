package tokenendpoint

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/devicecode"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	dcgrant "github.com/libraz/go-oidc-provider/internal/grants/devicecode"
	"github.com/libraz/go-oidc-provider/internal/grants/pollgrant"
	"github.com/libraz/go-oidc-provider/internal/pollinterval"
	"github.com/libraz/go-oidc-provider/op/store"
)

// handleDeviceCode implements the "grant_type=urn:ietf:params:oauth:
// grant-type:device_code" branch of RFC 8628 §3.4. The orchestration
// mirrors the other built-in grant handlers: client authentication,
// DPoP / mTLS verification, record lookup, polling discipline, the
// devicecode authorization gates, atomic record consume, and credential
// mint. The flow short-circuits on every gate so a poll the OP refuses
// never advances state on the substore.
//
// The persistence boundary lives entirely inside this function: the
// substore mutates exactly twice per successful poll (RecordPoll for
// the slow_down ladder and Consume for the single-use guarantee), and
// no token write coordinates a transaction with the device-code row
// (the substore is intentionally outside the transactional cluster
// because the approve→consume CAS already provides single-use; see
// the godoc on [store.DeviceCodeStore]).
func handleDeviceCode(w http.ResponseWriter, r *http.Request, deps Deps) {
	ctx := r.Context()
	if deps.DeviceCodes == nil {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errUnsupportedGrantType,
			"grant_type is not supported")
		return
	}
	// Proof verification, client authentication, and the proof's
	// replay marking run in the order [authenticateWithDPoP] documents.
	dpopOut, client, ok := authenticateWithDPoP(ctx, w, r, deps, grantTypeDeviceCode)
	if !ok {
		return
	}
	in, ok := parseDeviceCodeRequest(w, r)
	if !ok {
		return
	}
	binding, _, ok := bindRequest(w, r, deps, client, dpopOut)
	if !ok {
		return
	}
	rec, ok := lookupDeviceCode(ctx, w, deps, in.DeviceCode, client.ID)
	if !ok {
		return
	}
	if !applyPollDecision(ctx, w, deps, rec, in.DeviceCode, client.ID) {
		return
	}
	authorized, reason, ok := authorizeDeviceCodePoll(w, deps, client, rec, binding)
	if !ok {
		emitDeviceCodeReject(ctx, deps, client.ID, reason)
		return
	}
	user, err := lookupLiveSubject(ctx, deps, authorized.Subject)
	if err != nil {
		if errors.Is(err, errSubjectDeprovisioned) {
			retireDeprovisionedDeviceCode(ctx, deps, client.ID, authorized.Subject, in.DeviceCode)
		}
		writeSubjectLookupError(w, err)
		return
	}
	issued, err := preparePolledResponse(ctx, deps, client, polledRedemption{
		Subject:  authorized.Subject,
		Scope:    authorized.Scope,
		Audience: authorized.Audience,
		AuthTime: authorized.AuthTime,
	}, user, binding, polledIssuance{
		GrantID: devicecode.GrantID(in.DeviceCode),
		Origin:  store.RefreshOriginDeviceCode,
	})
	if err != nil {
		endpointsupport.WriteServerError(w)
		return
	}
	if !consumeDeviceCode(ctx, w, deps, in.DeviceCode) {
		issued.cleanup(ctx, deps)
		return
	}
	// A RevokeSubject that listed the grant while the credentials were being
	// persisted could not retire what was written after it; refuse here.
	if !refuseIssuanceUnderClosedGrant(ctx, w, deps, issued.issuedUnder(rec.IssuedAt), "device_code rejected") {
		return
	}
	emitDeviceCodeIssued(ctx, deps, deviceCodeIssuedExtras{
		ClientID:         client.ID,
		Subject:          authorized.Subject,
		Audience:         authorized.Audience,
		SenderConstraint: authorized.SenderConstraint,
		Scopes:           authorized.Scope,
	})
	writeSuccess(w, issued.response)
}

// deviceCodeInputs is the de-structured view of the form parameters
// the handler consumes for the device_code grant.
type deviceCodeInputs struct {
	DeviceCode string
}

// parseDeviceCodeRequest validates the required form fields. RFC 8628
// §3.4 names device_code as the only required parameter; the
// grant_type / client authentication parameters are validated by the
// shared dispatcher.
func parseDeviceCodeRequest(w http.ResponseWriter, r *http.Request) (deviceCodeInputs, bool) {
	in := deviceCodeInputs{DeviceCode: r.PostForm.Get("device_code")}
	if in.DeviceCode == "" {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest, "device_code is required")
		return deviceCodeInputs{}, false
	}
	return in, true
}

// applyPollDecision computes the polling decision per RFC 8628 §3.5
// and short-circuits the wire response on every non-emit branch. The
// helper also stamps the LastPolledAt observation (for the next
// slow_down ladder step) and persists the raised interval on
// slow_down. It returns true when the decision is "emit" — the only
// branch that lets the caller proceed to authorization gates and
// credential issuance.
func applyPollDecision(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	rec *store.DeviceCode,
	deviceCode, clientID string,
) bool {
	now := deps.now().UTC()
	decision := devicecode.DecidePoll(devicecode.PollInput{
		Now:               now,
		LastPolledAt:      derefTime(rec.LastPolledAt),
		EffectiveInterval: rec.Interval,
		ExpiresAt:         rec.ExpiresAt,
		Approved:          rec.Status == store.DeviceCodeStatusApproved,
		Denied:            rec.Status == store.DeviceCodeStatusDenied,
		Consumed:          rec.Status == store.DeviceCodeStatusConsumed,
		PollViolations:    rec.PollViolations,
	})
	spec := pollSpec{
		observationFailedEvent:   devicecode.AuditPollObservationFailed,
		observationFailedMessage: "device_code poll observation persistence failed; slow_down ladder may read stale LastPolledAt",
		recordPoll: func(ctx context.Context, at time.Time, interval time.Duration) error {
			return deps.DeviceCodes.RecordPoll(ctx, deviceCode, at, interval)
		},
		reject: func(ctx context.Context, code string) { emitDeviceCodeReject(ctx, deps, clientID, code) },
		slowDown: func(ctx context.Context, d pollinterval.Output) {
			emitDeviceCodeSlowDown(ctx, deps, clientID, rec.Interval, d.NextInterval)
			if d.CountThisAsViolation {
				strikes, err := deps.DeviceCodes.IncrementPollViolation(ctx, deviceCode)
				if err == nil && strikes >= devicecode.MaxPollViolations {
					_ = deps.DeviceCodes.Deny(ctx, deviceCode, "poll_abuse")
				}
			}
		},
		expiredDescription:  "device_code expired or already consumed",
		redeemedDescription: "device_code expired or already consumed",
	}
	return applyPollOutcome(ctx, w, deps, spec, decision, now, rec.Interval, clientID)
}

// lookupDeviceCode resolves the polling record from the substore and
// enforces the client_id binding. A missing record collapses to
// expired_token per RFC 8628 §3.5; a client mismatch collapses to
// invalid_grant so an attacker cannot probe for a known device_code
// across client identities.
func lookupDeviceCode(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	deviceCode, clientID string,
) (*store.DeviceCode, bool) {
	rec, err := deps.DeviceCodes.FindByDeviceCode(ctx, deviceCode)
	if err == nil && rec == nil {
		// A nil record alongside a nil error violates the store contract;
		// a device_code the backend cannot produce is treated as unknown.
		err = store.ErrNotFound
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			emitDeviceCodeReject(ctx, deps, clientID, errExpiredToken)
			endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errExpiredToken,
				"device_code expired or already consumed")
			return nil, false
		}
		endpointsupport.WriteServerError(w)
		return nil, false
	}
	if rec.ClientID != clientID {
		emitDeviceCodeReject(ctx, deps, clientID, errInvalidGrant)
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidGrant, "device_code rejected")
		return nil, false
	}
	return rec, true
}

// authorizeDeviceCodePoll wraps [dcgrant.Authorize] and maps its
// sentinels onto wire codes. The function returns the authorised
// projection on success or writes the wire response and returns
// (nil, false) on rejection. Sentinels mostly collapse to
// invalid_grant; the cnf-binding mismatch / missing cases are the
// principal "downgrade attempt" signal so they ride the same wire
// code as a stale code per RFC 6749 §5.2.
func authorizeDeviceCodePoll(
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	rec *store.DeviceCode,
	binding tokenBinding,
) (*dcgrant.Authorized, string, bool) {
	authorized, err := dcgrant.Authorize(dcgrant.AuthorizeInput{
		Client:                client,
		Record:                rec,
		PresentedDPoPJKT:      binding.DPoPJKT,
		PresentedMTLSCertS256: binding.MTLSThumbprint,
	})
	if err != nil {
		code, status, description := deviceCodeAuthError(err)
		endpointsupport.WriteOAuthError(w, status, code, description)
		return nil, code, false
	}
	if !checkTokenScopeAllowlist(w, deps, client.ID, authorized.Scope) {
		return nil, errInvalidScope, false
	}
	return authorized, "", true
}

// deviceCodeAuthError translates the dcgrant.Err* sentinels onto the wire
// code, HTTP status and description. The mapping mirrors the comments on
// the package sentinels (internal/grants/devicecode/devicecode.go):
//
//   - ErrGrantNotPermitted     → unauthorized_client.
//   - ErrScopeForbidden        → invalid_scope.
//   - ErrCnfBindingMismatch /
//     ErrCnfBindingMissing     → invalid_grant.
//   - ErrSubjectMissing        → invalid_grant (OIDC Core 1.0 §2; the
//     approval names no end user, so no credential can be minted).
//   - ErrPendingApproval       → authorization_pending (defensive;
//     [DecidePoll] should have caught this case already).
//   - ErrDenied                → access_denied (same defensive note).
//   - ErrExpiredOrConsumed     → expired_token (same defensive note).
//   - default                  → server_error (programmer bug).
func deviceCodeAuthError(err error) (code string, status int, description string) {
	if errors.Is(err, dcgrant.ErrExpiredOrConsumed) {
		return errExpiredToken, http.StatusBadRequest, "device_code expired or already consumed"
	}
	return pollAuthError(err, pollAuthMap{
		Errors: pollgrant.Errors{
			NotPermitted:   dcgrant.ErrGrantNotPermitted,
			SubjectMissing: dcgrant.ErrSubjectMissing,
			CnfMissing:     dcgrant.ErrCnfBindingMissing,
			CnfMismatch:    dcgrant.ErrCnfBindingMismatch,
			ScopeForbidden: dcgrant.ErrScopeForbidden,
		},
		Pending:   dcgrant.ErrPendingApproval,
		Denied:    dcgrant.ErrDenied,
		Grant:     "device_code",
		CnfRecord: "device-authorization",
		NoSubject: "device authorization is not associated with an end user",
	})
}

// retireDeprovisionedDeviceCode spends an approval whose subject no
// longer exists and records the refusal. The grant is allocated only at
// redemption, so no credential exists yet to tear down. A Consume fault
// is dropped: the approval then lapses on its TTL, and every poll until
// then meets the same subject lookup.
func retireDeprovisionedDeviceCode(ctx context.Context, deps Deps, clientID, subject, deviceCode string) {
	_, _ = deps.DeviceCodes.Consume(ctx, deviceCode)
	emitDeviceCodeReject(ctx, deps, clientID, errInvalidGrant)
	retireDeprovisionedGrant(ctx, deps, deprovisionedRedemption{
		ClientID:  clientID,
		Subject:   subject,
		GrantType: grantTypeDeviceCode,
	})
}

// consumeDeviceCode atomically transitions the record from Approved
// to Consumed. A racing successful
// poll surfaces as [store.ErrAlreadyConsumed] from the substore; the
// library maps that to expired_token because RFC 8628 §3.5 reserves
// the wire code for "the device_code has expired or has been
// consumed", which describes the racing-poll case verbatim.
func consumeDeviceCode(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	deviceCode string,
) bool {
	consumed, err := deps.DeviceCodes.Consume(ctx, deviceCode)
	if err == nil && consumed == nil {
		// A nil record alongside a nil error violates the store contract;
		// without the consumed record there is nothing to issue against.
		err = store.ErrNotFound
	}
	if err != nil {
		switch {
		case errors.Is(err, store.ErrAlreadyConsumed),
			errors.Is(err, store.ErrNotFound):
			endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errExpiredToken,
				"device_code expired or already consumed")
		case errors.Is(err, store.ErrConflict):
			endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidGrant,
				"device_code is not in a consumable state")
		default:
			endpointsupport.WriteServerError(w)
		}
		return false
	}
	return true
}

// deviceCodeIssuedExtras bundles the audit extras the issuance path
// emits. Splitting into a struct keeps the [emitDeviceCodeIssued]
// signature well under the project's parameter-count cap and lines
// the call site up with the audit catalogue documented in
// [devicecode.AuditTokenIssued].
type deviceCodeIssuedExtras struct {
	ClientID         string
	Subject          string
	Scopes           []string
	Audience         []string
	SenderConstraint string
}

// emitDeviceCodeIssued logs a successful device_code redemption.
// The audit name matches [devicecode.AuditTokenIssued] and the extras
// agree with the catalogue documented in
// internal/devicecode/audit.go.
func emitDeviceCodeIssued(ctx context.Context, deps Deps, in deviceCodeIssuedExtras) {
	deps.audit().Emit(ctx, audit.Event{
		Name:     devicecode.AuditTokenIssued,
		Level:    audit.LevelInfo,
		Message:  "device_code redeemed for tokens",
		ActorID:  in.Subject,
		ClientID: in.ClientID,
		Extras: map[string]any{
			"scope":             append([]string(nil), in.Scopes...),
			"audience":          append([]string(nil), in.Audience...),
			"sender_constraint": in.SenderConstraint,
		},
	})
}

// emitDeviceCodeReject logs a rejected poll. The audit name matches
// [devicecode.AuditTokenRejected]; reason is the wire error string
// the OP returned ("authorization_pending", "slow_down",
// "access_denied", "expired_token", or "invalid_grant").
func emitDeviceCodeReject(ctx context.Context, deps Deps, clientID, reason string) {
	deps.audit().Emit(ctx, audit.Event{
		Name:     devicecode.AuditTokenRejected,
		Level:    audit.LevelInfo,
		Message:  "device_code poll rejected",
		ClientID: clientID,
		Extras: map[string]any{
			"reason": reason,
		},
	})
}

// emitDeviceCodeSlowDown logs a slow_down rejection alongside the
// rejection event so SOC tooling can see the ladder step
// without parsing the audit name. observed is the gap the device
// polled at; effective is the bar the poll was measured against;
// next is the raised bar.
func emitDeviceCodeSlowDown(ctx context.Context, deps Deps, clientID string, effective, next time.Duration) {
	deps.audit().Emit(ctx, audit.Event{
		Name:     devicecode.AuditTokenSlowDown,
		Level:    audit.LevelWarn,
		Message:  "device_code poll triggered slow_down",
		ClientID: clientID,
		Extras: map[string]any{
			"effective_interval": effective.String(),
			"next_interval":      next.String(),
		},
	})
}
