package tokenendpoint

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/devicecode"
	dcgrant "github.com/libraz/go-oidc-provider/internal/grants/devicecode"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// errAuthorizationPending / errSlowDown / errAccessDenied / errExpiredToken
// are the RFC 8628 §3.5 wire codes specific to the device_code grant.
// They are scoped to this file so the rest of the token endpoint never
// reaches them by accident; the values match the wire form verbatim.
const (
	errAuthorizationPending = "authorization_pending"
	errSlowDown             = "slow_down"
	errAccessDenied         = "access_denied"
	errExpiredToken         = "expired_token"
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
	in, ok := parseDeviceCodeRequest(w, r)
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
	rec, ok := lookupDeviceCode(ctx, w, deps, in.DeviceCode, client.ID)
	if !ok {
		return
	}
	if !applyPollDecision(ctx, w, deps, rec, in.DeviceCode, client.ID) {
		return
	}
	authorized, ok := authorizeDeviceCodePoll(w, deps, client, rec, binding)
	if !ok {
		emitDeviceCodeReject(ctx, deps, client.ID, errInvalidGrant)
		return
	}
	consumed, ok := consumeDeviceCode(ctx, w, deps, in.DeviceCode)
	if !ok {
		return
	}
	issueDeviceCodeResponse(ctx, w, deps, client, consumed, authorized, binding)
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
		writeError(w, http.StatusBadRequest, errInvalidRequest, "device_code is required")
		return deviceCodeInputs{}, false
	}
	return in, true
}

// applyPollDecision computes the polling decision per RFC 8628 §3.5
// and short-circuits the wire response on every non-emit branch. The
// helper also stamps the LastPolledAt observation (for the next
// slow_down ladder step) and persists the doubled interval on
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
	})
	// Stamp the poll timestamp AND the (possibly escalated) interval
	// before any further branching so the next poll's slow_down ladder
	// sees the current observation. On a non-slow_down decision the
	// substore preserves the existing Interval (RecordPoll treats a
	// non-escalating value as no-op on that field). A store fault here
	// is non-fatal: the worst case is the next poll gets the same
	// decision because LastPolledAt / Interval are stale, which is the
	// correct fail-open behaviour for a transient substore outage.
	nextInterval := rec.Interval
	if decision.Decision == devicecode.PollDecisionSlowDown {
		nextInterval = decision.NextInterval
	}
	_ = deps.DeviceCodes.RecordPoll(ctx, deviceCode, now, nextInterval)
	switch decision.Decision {
	case devicecode.PollDecisionAuthorizationPending:
		emitDeviceCodeReject(ctx, deps, clientID, errAuthorizationPending)
		writeError(w, http.StatusBadRequest, errAuthorizationPending,
			"authorization request is still pending")
		return false
	case devicecode.PollDecisionSlowDown:
		emitDeviceCodeSlowDown(ctx, deps, clientID, rec.Interval, decision.NextInterval)
		writeError(w, http.StatusBadRequest, errSlowDown,
			"polling interval has been increased; back off and retry")
		return false
	case devicecode.PollDecisionAccessDenied:
		emitDeviceCodeReject(ctx, deps, clientID, errAccessDenied)
		writeError(w, http.StatusBadRequest, errAccessDenied,
			"authorization request was denied")
		return false
	case devicecode.PollDecisionExpiredToken:
		emitDeviceCodeReject(ctx, deps, clientID, errExpiredToken)
		writeError(w, http.StatusBadRequest, errExpiredToken,
			"device_code expired or already consumed")
		return false
	case devicecode.PollDecisionEmit:
		return true
	case devicecode.PollDecisionInvalid:
		fallthrough
	default:
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return false
	}
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
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			emitDeviceCodeReject(ctx, deps, clientID, errExpiredToken)
			writeError(w, http.StatusBadRequest, errExpiredToken,
				"device_code expired or already consumed")
			return nil, false
		}
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return nil, false
	}
	if rec.ClientID != clientID {
		emitDeviceCodeReject(ctx, deps, clientID, errInvalidGrant)
		writeError(w, http.StatusBadRequest, errInvalidGrant, "device_code rejected")
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
) (*dcgrant.Authorized, bool) {
	authorized, err := dcgrant.Authorize(dcgrant.AuthorizeInput{
		Client:                client,
		Record:                rec,
		PresentedDPoPJKT:      binding.DPoPJKT,
		PresentedMTLSCertS256: binding.MTLSThumbprint,
	})
	if err != nil {
		writeDeviceCodeAuthError(w, err)
		return nil, false
	}
	if !checkTokenScopeAllowlist(w, deps, client.ID, authorized.Scope) {
		return nil, false
	}
	return authorized, true
}

// writeDeviceCodeAuthError translates the [dcgrant.Err*] sentinels
// onto wire codes. The mapping mirrors the comments on the package
// sentinels (internal/grants/devicecode/devicecode.go):
//
//   - ErrGrantNotPermitted     → unauthorized_client.
//   - ErrScopeForbidden        → invalid_scope.
//   - ErrCnfBindingMismatch /
//     ErrCnfBindingMissing     → invalid_grant.
//   - ErrPendingApproval       → authorization_pending (defensive;
//     [DecidePoll] should have caught this case already).
//   - ErrDenied                → access_denied (same defensive note).
//   - ErrExpiredOrConsumed     → expired_token (same defensive note).
//   - default                  → server_error (programmer bug).
func writeDeviceCodeAuthError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, dcgrant.ErrGrantNotPermitted):
		writeError(w, http.StatusBadRequest, errUnauthorizedClient,
			"client is not authorized for the device_code grant")
	case errors.Is(err, dcgrant.ErrScopeForbidden):
		writeError(w, http.StatusBadRequest, errInvalidScope,
			"granted scope exceeds the client's registered set")
	case errors.Is(err, dcgrant.ErrCnfBindingMismatch),
		errors.Is(err, dcgrant.ErrCnfBindingMissing):
		writeError(w, http.StatusBadRequest, errInvalidGrant,
			"sender-constraint binding does not match the device-authorization record")
	case errors.Is(err, dcgrant.ErrPendingApproval):
		writeError(w, http.StatusBadRequest, errAuthorizationPending,
			"authorization request is still pending")
	case errors.Is(err, dcgrant.ErrDenied):
		writeError(w, http.StatusBadRequest, errAccessDenied,
			"authorization request was denied")
	case errors.Is(err, dcgrant.ErrExpiredOrConsumed):
		writeError(w, http.StatusBadRequest, errExpiredToken,
			"device_code expired or already consumed")
	default:
		writeError(w, http.StatusInternalServerError, errServerError, "")
	}
}

// consumeDeviceCode atomically transitions the record from Approved
// to Consumed and returns the consumed snapshot. A racing successful
// poll surfaces as [store.ErrAlreadyConsumed] from the substore; the
// library maps that to expired_token because RFC 8628 §3.5 reserves
// the wire code for "the device_code has expired or has been
// consumed", which describes the racing-poll case verbatim.
func consumeDeviceCode(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	deviceCode string,
) (*store.DeviceCode, bool) {
	consumed, err := deps.DeviceCodes.Consume(ctx, deviceCode)
	if err != nil {
		switch {
		case errors.Is(err, store.ErrAlreadyConsumed),
			errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusBadRequest, errExpiredToken,
				"device_code expired or already consumed")
		case errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusBadRequest, errInvalidGrant,
				"device_code is not in a consumable state")
		default:
			writeError(w, http.StatusInternalServerError, errServerError, "")
		}
		return nil, false
	}
	return consumed, true
}

// issueDeviceCodeResponse mints the access token, optionally an
// id_token (only when scope contains openid), and optionally a
// refresh token (only when [clientPermitsRefresh] AND the granted
// scope satisfies the OIDC Core 1.0 §11 / per-client refresh gate).
// The function reuses [mintAccessToken] / [maybeIssueRefreshToken]
// so the cnf-claim plumbing, opaque-format dispatch, and audit
// emission all stay aligned with the authorization_code path.
//
// audience selection: the /device_authorization endpoint rejects
// multi-resource requests with invalid_target, so [authorized.Audience]
// holds at most one canonicalised entry. The handler reads index 0
// (or empty when none was registered), matching the access-token
// aud claim's single-entry encoding.
func issueDeviceCodeResponse(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	consumed *store.DeviceCode,
	authorized *dcgrant.Authorized,
	binding tokenBinding,
) {
	now := deps.now().UTC()
	resource := ""
	if len(authorized.Audience) > 0 {
		resource = authorized.Audience[0]
	}
	// auth_time is the wall-clock at which the end user completed the
	// verification ceremony — store.DeviceCodeStore.Approve stamps it
	// onto the record. A zero value means the substore did not retain
	// an auth_time (legacy records persisted before the column was
	// introduced); the encoder omits the claim in that case, matching
	// OIDC Core 1.0 §2's "OPTIONAL unless the client requires it"
	// posture. Clients that set RequireAuthTime block id_token
	// issuance via requireAuthTimeForIDToken below when the value is
	// zero.
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
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	var idToken string
	if oidcscope.ContainsOpenID(authorized.Scope) {
		idToken, err = mintDeviceCodeIDToken(deps, deviceCodeIDTokenInput{
			Subject:     publicSubject,
			ClientID:    client.ID,
			AccessToken: accessToken,
			Now:         now,
			AuthTime:    authTime,
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
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	emitDeviceCodeIssued(ctx, deps, deviceCodeIssuedExtras{
		ClientID:         client.ID,
		Subject:          authorized.Subject,
		Scope:            authorized.Scope,
		Audience:         authorized.Audience,
		SenderConstraint: authorized.SenderConstraint,
		Scopes:           authorized.Scope,
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

// deviceCodeIDTokenInput collects the parameters
// [mintDeviceCodeIDToken] needs. The struct exists so the function
// stays under the project's parameter-count cap; the device flow
// does not have a code for c_hash and does not preserve a nonce
// across the verification ceremony, so those fields are absent.
type deviceCodeIDTokenInput struct {
	Subject     string
	ClientID    string
	AccessToken string
	Now         time.Time
	AuthTime    int64
}

// mintDeviceCodeIDToken signs the id_token issued in response to a
// device_code redemption. at_hash is populated per OIDC Core §3.1.3.6
// because the access token is bound to the same redemption and
// matches the spec's "ID Token issued from a Token Endpoint" shape.
// c_hash is omitted because the device flow has no authorization
// code to bind. nonce is omitted because RFC 8628 has no path for
// the device to commit one at /device_authorization (the embedder
// MAY surface one through the verification page, but the v0.9.1
// substore does not retain it). auth_time is populated when the
// substore stamped a non-zero value at Approve time; the encoder
// omits the claim on zero.
func mintDeviceCodeIDToken(deps Deps, in deviceCodeIDTokenInput) (string, error) {
	claims := tokens.IDTokenClaims{
		Issuer:    deps.Issuer,
		Subject:   in.Subject,
		Audience:  []string{in.ClientID},
		IssuedAt:  in.Now.Unix(),
		ExpiresAt: tokens.ExpiresIn(in.Now, deps.IDTokenTTL),
		AtHash:    tokens.Hash(in.AccessToken),
		AuthTime:  in.AuthTime,
	}
	return tokens.SignIDToken(activeSigningKey(deps), claims)
}

// authTimeUnix collapses a wall-clock auth_time into the seconds-
// since-epoch value the id_token claim encodes. A zero time
// returns zero so the encoder's omit-on-zero behaviour stays
// active and the claim is left absent on legacy records.
func authTimeUnix(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// derefTime returns the dereferenced value of t, or the zero time
// when t is nil. The substore exposes [store.DeviceCode.LastPolledAt]
// as a *time.Time so an embedder can distinguish "never polled" from
// "polled at the epoch"; [devicecode.PollInput] consumes a flat
// time.Time, so we collapse here at the boundary.
func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// deviceCodeIssuedExtras bundles the audit extras the issuance path
// emits. Splitting into a struct keeps the [emitDeviceCodeIssued]
// signature well under the project's parameter-count cap and lines
// the call site up with the audit catalogue documented in
// [internal/devicecode.AuditTokenIssued].
type deviceCodeIssuedExtras struct {
	ClientID         string
	Subject          string
	Scope            []string
	Scopes           []string
	Audience         []string
	SenderConstraint string
}

// emitDeviceCodeIssued logs a successful device_code redemption.
// The audit name matches [devicecode.AuditTokenIssued] and the extras
// agree with the catalogue documented in
// [internal/devicecode/audit.go].
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
// rejection event so SOC tooling can see the doubling ladder
// without parsing the audit name. observed is the gap the device
// polled at; effective is the bar before doubling; next is the
// elevated bar.
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
