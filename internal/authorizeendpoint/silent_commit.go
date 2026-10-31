package authorizeendpoint

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/store"
)

// mintAndRedirect persists a fresh authorization code bound to the existing
// grant and redirects the browser to redirect_uri?code=...&state=....
func mintAndRedirect(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
	hint authorizeHint,
) {
	if active == nil || (hint.grant == nil && hint.autoGrant == nil) {
		// Defensive: the dispatcher only reaches mintAndRedirect when
		// both are non-nil. Surface a server_error redirect so a
		// future regression is observable.
		emitAuthorizeError(w, r, deps, req, errServerError, "missing session or grant for silent mint")
		return
	}
	reported, err := reportSessionAuthContext(r.Context(), r, deps, req, active.Session.Subject,
		authn.State{}, sessionAuthContext(active))
	if err != nil {
		code, description, _ := terminalRefusal(err)
		emitAuthorizeError(w, r, deps, req, code, description)
		return
	}
	codeID, err := newRandomB64(codeByteLength)
	if err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not allocate code")
		return
	}
	durableGrant, parFailure, err := commitSilentAuthorization(
		r.Context(),
		deps,
		req,
		client,
		active,
		hint,
		reported,
		codeID,
	)
	if err != nil && parFailure {
		emitAuthorizeError(w, r, deps, req, errAccessDenied, "request_uri is no longer valid")
		return
	}
	if err != nil {
		// A terminal-validation refusal keeps its own wire code: the
		// silent exit is subject to the same invariants as the
		// interactive one, so an RP sees the same answer whichever exit
		// the request happened to take. Anything else is a commit
		// failure.
		if code, description, _ := terminalRefusal(err); code != errServerError {
			emitAuthorizeError(w, r, deps, req, code, description)
			return
		}
		emitAuthorizeError(w, r, deps, req, errServerError, "could not commit authorization code")
		return
	}
	if hint.autoGrant != nil {
		deps.auditEmitter().Emit(r.Context(), audit.Event{
			Name:      opAuditConsentGrantedFirstParty,
			Level:     audit.LevelInfo,
			Message:   "first-party consent auto-granted",
			ActorID:   active.Session.Subject,
			ClientID:  client.ID,
			SessionID: active.Session.ID,
			IP:        auditRemoteIP(r, deps),
			UserAgent: truncateUserAgent(r.UserAgent()),
			Extras: map[string]any{
				"grant_id": durableGrant.ID,
				"scope":    append([]string(nil), req.Scope...),
			},
		})
	}
	deps.auditEmitter().Emit(r.Context(), audit.Event{
		Name:      opAuditCodeIssued,
		Level:     audit.LevelInfo,
		Message:   "authorization code issued",
		ActorID:   active.Session.Subject,
		ClientID:  client.ID,
		SessionID: active.Session.ID,
		Extras: map[string]any{
			// The code itself is a bearer credential for the whole
			// TTL, so the audit stream carries only its irreversible
			// digest. The token endpoint stamps the same key with the
			// same transform, so the two records still correlate.
			"code_id":  audit.Fingerprint(codeID),
			"grant_id": durableGrant.ID,
			"scope":    append([]string(nil), req.Scope...),
		},
	})
	emitAuthorizeSuccess(w, r, deps, req, codeID)
}

// commitSilentAuthorization persists the silent authorization — the grant
// the code hangs off and the code itself — inside one transaction, and
// reports whether a failure came from the PAR consumption so the caller
// can answer access_denied instead of server_error.
//
// It shares [retryOnGrantConflict] with the interaction-completion path
// because it shares the hazard: a returning user with two tabs open
// drives two silent mints for the same (subject, client), and a backend
// that versions the grant record fails whichever one reads first. The
// caller draws codeID once, before the first attempt, so a retry rewrites
// the same code rather than minting a second; everything the body writes
// is staged inside the transaction it opens, so an attempt that lost left
// neither a code nor a consumed request_uri behind.
func commitSilentAuthorization(
	ctx context.Context,
	deps resolved,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
	hint authorizeHint,
	reported grantAuthContext,
	codeID string,
) (*store.Grant, bool, error) {
	return retryOnGrantConflict(ctx, func() (*store.Grant, bool, error) {
		return attemptSilentAuthorization(ctx, deps, req, client, active, hint, reported, codeID)
	})
}

func attemptSilentAuthorization(
	ctx context.Context,
	deps resolved,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
	hint authorizeHint,
	reported grantAuthContext,
	codeID string,
) (*store.Grant, bool, error) {
	if deps.Transactions == nil {
		return nil, false, errors.New("authorizeendpoint: transactional store unavailable")
	}
	tx, err := deps.Transactions.BeginTx(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("authorizeendpoint: begin silent transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	txDeps := deps
	txDeps.PARs = tx.PushedAuthRequests()
	txDeps.Codes = tx.AuthorizationCodes()
	txDeps.Grants = tx.Grants()
	durableGrant, err := resolveSilentGrant(ctx, txDeps, req, hint, reported)
	if err != nil {
		return nil, false, err
	}
	// The silent exit's terminal gate. The decision matrix approved this
	// mint against the session and the grant as they were when the
	// request arrived; the grant has since been re-read (and possibly
	// re-stamped) inside this transaction, so the invariants are settled
	// here against what the code is actually about to point at.
	//
	// The resolved authentication is discarded rather than stamped: it is
	// the session's record, and resolveSilentGrant has already written
	// what that record reports to this client onto the grant.
	exit, backing := silentExit(hint, active)
	if _, err := validateTerminalAuthorization(ctx, txDeps, req, terminalAuthorization{
		Exit:                   exit,
		Backing:                backing,
		Subject:                active.Session.Subject,
		Scope:                  req.Scope,
		ConsentFromCachedGrant: hint.autoGrant == nil,
		Grant:                  durableGrant,
	}); err != nil {
		return nil, false, err
	}
	now := deps.now().UTC()
	code := &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             durableGrant.Subject,
		GrantID:             durableGrant.ID,
		RedirectURI:         req.RedirectURI,
		Scope:               append([]string(nil), req.Scope...),
		Resource:            req.Resource,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
		State:               req.State,
		DPoPJKT:             req.DPoPJKT,

		AuthTime:              reported.AuthTime,
		ACR:                   reported.ACR,
		AMR:                   slices.Clone(reported.AMR),
		AuthorizationDetails:  codeAuthorizationDetails(req, durableGrant),
		Claims:                authorize.EncodeClaimsToGrant(req.Claims),
		AuthorizationRecorded: true,

		ExpiresAt: now.Add(deps.AuthCodeTTL),
		CreatedAt: now,
	}
	if err := consumePARIfNeeded(ctx, txDeps, req); err != nil {
		return nil, true, err
	}
	if err := txDeps.Codes.Save(ctx, code); err != nil {
		return nil, false, fmt.Errorf("authorizeendpoint: save silent code: %w", err)
	}
	if err := tx.Commit(); err != nil {
		// A database may durably commit and then lose the ACK. Release the
		// transaction handle before probing the outer store.
		_ = tx.Rollback()
		committedCode, findErr := deps.Codes.Find(ctx, codeID)
		if findErr != nil || !silentAuthorizationCodeMatches(committedCode, code) {
			return nil, false, fmt.Errorf("authorizeendpoint: commit silent transaction: %w", err)
		}
	}
	return durableGrant, false, nil
}

// resolveSilentGrant produces the durable grant a silent mint hangs its
// code off: the auto-grant the first-party skip planned, or the cached
// grant the decision matrix picked, re-read inside the transaction and
// re-stamped with what this request carries. reported is the
// authentication context [reportAuthContext] resolved for this request.
//
// It settles the record's identity and contents only. Whether that
// record describes an authorization the request may actually be served
// from is [validateTerminalAuthorization]'s call, which applies one set
// of rules to every exit that can emit a code.
func resolveSilentGrant(
	ctx context.Context,
	deps resolved,
	req *authorize.Request,
	hint authorizeHint,
	reported grantAuthContext,
) (*store.Grant, error) {
	if hint.autoGrant != nil {
		planned := *hint.autoGrant
		planned.AuthTime = reported.AuthTime
		planned.ACR = reported.ACR
		planned.AMR = slices.Clone(reported.AMR)
		return upsertGrant(ctx, deps, planned)
	}
	grant, err := deps.Grants.Find(ctx, hint.grant.ID)
	if err != nil {
		return nil, fmt.Errorf("authorizeendpoint: reload silent grant: %w", err)
	}
	if grant == nil || grant.ID != hint.grant.ID {
		return nil, errors.New("authorizeendpoint: authorization grant unavailable")
	}
	// The grant may have been recorded by an older ceremony — or an
	// earlier request — than the one now being served. Re-stamp both
	// halves of what the grant carries forward so the code points at this
	// request's authorization rather than a previous one's:
	//
	//   - the session's authentication context as reported to this
	//     client, so the id_token reports the authentication the decision
	//     matrix just validated max_age / acr_values against instead of a
	//     stale (and possibly stronger) one;
	//   - the OIDC Core 1.0 §5.5 claims payload, so the token and
	//     userinfo endpoints project what this request asked for. Without
	//     it a returning subject who adds a claims parameter to an
	//     otherwise-covered request is served silently against the
	//     payload of the authorization that first created the grant.
	//
	// A nil payload leaves the grant's claims untouched, matching
	// reuseOrCreateGrant's rule that "absent" is not "erase". The
	// interactive and auto-grant paths do the equivalent through
	// upsertGrant.
	changed := stampGrantAuthContext(grant, reported)
	if encoded := authorize.EncodeClaimsToGrant(req.Claims); encoded != nil &&
		!claimsPayloadEqual(grant.Claims, encoded) {
		grant.Claims = encoded
		changed = true
	}
	if changed {
		grant.UpdatedAt = deps.now().UTC()
		if err := deps.Grants.Save(ctx, grant); err != nil {
			return nil, fmt.Errorf("authorizeendpoint: refresh silent grant auth context: %w", err)
		}
	}
	return grant, nil
}

func silentAuthorizationCodeMatches(actual, expected *store.AuthorizationCode) bool {
	if actual == nil || expected == nil {
		return false
	}
	return actual.ID == expected.ID &&
		actual.ClientID == expected.ClientID &&
		actual.Subject == expected.Subject &&
		actual.GrantID == expected.GrantID &&
		actual.RedirectURI == expected.RedirectURI &&
		slices.Equal(actual.Scope, expected.Scope) &&
		actual.Resource == expected.Resource &&
		actual.CodeChallenge == expected.CodeChallenge &&
		actual.CodeChallengeMethod == expected.CodeChallengeMethod &&
		actual.Nonce == expected.Nonce &&
		actual.State == expected.State &&
		actual.DPoPJKT == expected.DPoPJKT
}
