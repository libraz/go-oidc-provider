package authorizeendpoint

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

const completionIntentVersion = 1

func prepareCompletionIntent(
	r *http.Request,
	deps resolved,
	rec *store.Interaction,
	authnState authn.State,
	result interaction.Result,
	recorded grantAuthContext,
	reported grantAuthContext,
	decision scopeDecision,
	requestedScope []string,
) (*authorize.CompletionIntent, error) {
	if len(deps.CompletionKey) < 32 {
		return nil, errors.New("authorizeendpoint: completion key unavailable")
	}
	active, err := resolveSessionWithoutTouch(r, deps)
	if err != nil {
		if !errors.Is(err, sessions.ErrCurrentSessionExpired) && !errors.Is(err, sessions.ErrCookieInvalid) {
			return nil, fmt.Errorf("authorizeendpoint: resolve session for completion intent: %w", err)
		}
		active = nil
	}
	establishment, err := deps.Sessions.PlanEstablishment(r.Context(), sessions.EstablishPlan{
		Active: active,
		Login: sessions.Login{
			Subject:  result.Subject,
			AuthTime: result.AuthTime,
			AMR:      slices.Clone(recorded.AMR),
			ACR:      recorded.ACR,
		},
		FreshAuthn:               len(authnState.Factors) > 0,
		StableSessionID:          deriveCompletionID(deps.CompletionKey, rec.ID, "session"),
		StableChooserGroupID:     deriveCompletionID(deps.CompletionKey, rec.ID, "chooser"),
		ChooserGroupID:           authnState.ChooserGroupID,
		ChooserSelectedSessionID: authnState.ChooserSelectedSessionID,
		ChooserAddAccount:        authnState.ChooserAddAccount,
		ChooserAddAccountGroupID: authnState.ChooserAddAccountGroupID,
		Now:                      deps.now(),
	})
	if err != nil {
		return nil, fmt.Errorf("authorizeendpoint: plan stable session: %w", err)
	}
	return &authorize.CompletionIntent{
		Version:    completionIntentVersion,
		CodeID:     deriveCompletionID(deps.CompletionKey, rec.ID, "code"),
		NewGrantID: deriveCompletionID(deps.CompletionKey, rec.ID, "grant"),
		Subject:    result.Subject,
		AuthTime:   result.AuthTime,
		ACR:        reported.ACR,
		AMR:        slices.Clone(reported.AMR),
		GrantScope: decision.grantScope(requestedScope),
		// DeclinedScope travels with the intent so a retried or resumed
		// completion applies the same grant amendment the ceremony
		// decided on. Recomputing it downstream is not possible: the
		// orchestrator state is gone by the time the completion is
		// replayed.
		DeclinedScope: decision.declined(),
		Session:       encodeCompletionSession(establishment),
	}, nil
}

func deriveCompletionID(key []byte, interactionID, label string) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("oidc-authorization-completion-v1\x00"))
	_, _ = mac.Write([]byte(label))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(interactionID))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func encodeCompletionSession(in sessions.Establishment) authorize.CompletionSessionIntent {
	return authorize.CompletionSessionIntent{
		Mode:              string(in.Mode),
		SessionID:         in.Record.ID,
		PreviousSessionID: in.PreviousSessionID,
		ChooserGroupID:    in.Record.ChooserGroupID,
		Subject:           in.Record.Subject,
		AuthTime:          in.Record.AuthTime,
		ACR:               in.Record.ACR,
		AMR:               slices.Clone(in.Record.AMR),
		ExpiresAt:         in.Record.ExpiresAt,
		CreatedAt:         in.Record.CreatedAt,
		UpdatedAt:         in.Record.UpdatedAt,
	}
}

func decodeCompletionSession(in authorize.CompletionSessionIntent) sessions.Establishment {
	return sessions.Establishment{
		Mode: sessions.EstablishMode(in.Mode),
		Record: store.Session{
			ID:             in.SessionID,
			Subject:        in.Subject,
			AuthTime:       in.AuthTime,
			AMR:            slices.Clone(in.AMR),
			ACR:            in.ACR,
			ChooserGroupID: in.ChooserGroupID,
			ExpiresAt:      in.ExpiresAt,
			CreatedAt:      in.CreatedAt,
			UpdatedAt:      in.UpdatedAt,
		},
		PreviousSessionID: in.PreviousSessionID,
	}
}

func persistCompletionIntent(
	ctx context.Context,
	deps resolved,
	rec *store.Interaction,
	state authorize.RequestState,
	intent *authorize.CompletionIntent,
) (*store.Interaction, authorize.RequestState, error) {
	state.Completion = intent
	raw, err := authorize.MarshalState(state)
	if err != nil {
		return nil, authorize.RequestState{}, fmt.Errorf(
			"authorizeendpoint: marshal completion intent: %w", err,
		)
	}
	cas, err := interactionCAS(deps)
	if err != nil {
		return nil, authorize.RequestState{}, err
	}
	next := *rec
	next.RawState = raw
	next.UpdatedAt = deps.now().UTC()
	if err := cas.CompareAndSwap(ctx, rec, &next); err == nil {
		return &next, state, nil
	} else if !errors.Is(err, store.ErrConflict) {
		return nil, authorize.RequestState{}, fmt.Errorf(
			"authorizeendpoint: persist completion intent: %w", err,
		)
	}

	// Another terminal POST won the immutable transition. Resume the winner's
	// intent instead of overwriting it or minting a second durable result.
	current, err := deps.Interactions.Find(ctx, rec.ID)
	if err == nil && current == nil {
		// A nil record alongside a nil error violates the store contract;
		// the winner's intent cannot be resumed without it.
		err = store.ErrNotFound
	}
	if err != nil {
		return nil, authorize.RequestState{}, fmt.Errorf(
			"authorizeendpoint: reload completion intent after conflict: %w", err,
		)
	}
	currentState, err := authorize.UnmarshalState(current.RawState)
	if err != nil {
		return nil, authorize.RequestState{}, fmt.Errorf(
			"authorizeendpoint: decode completion intent after conflict: %w", err,
		)
	}
	if currentState.Completion == nil ||
		currentState.Completion.Version != completionIntentVersion {
		return nil, authorize.RequestState{}, errors.New(
			"authorizeendpoint: interaction changed before completion intent claim",
		)
	}
	return current, currentState, nil
}

func resumeInteractionCompletion(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	rec *store.Interaction,
	state authorize.RequestState,
) {
	intent := state.Completion
	if intent == nil || intent.Version != completionIntentVersion {
		renderBrowserError(w, r, deps.Driver, http.StatusInternalServerError, errServerError, "authorization completion intent is invalid", "")
		return
	}
	if err := refreshCompletionSession(w, r, deps, intent); err != nil {
		renderServerError(w, r, deps, "could not refresh session", err)
		return
	}
	req := state.Library.ToRequest()
	code, _, err := ensureDurableCompletion(r.Context(), deps, req, intent)
	if err != nil {
		if errors.Is(err, errGrantNotOwned) {
			_ = deleteCompletionAnchor(r.Context(), deps, rec)
			cookie.ClearOn(w, cookie.InteractionProfile)
			cookie.ClearOn(w, cookie.CSRFProfile)
			emitAuthorizeError(w, r, deps, req, errInvalidGrant, "grant_id is not owned by this subject/client")
			return
		}
		if errors.Is(err, store.ErrAlreadyConsumed) {
			_ = deleteCompletionAnchor(r.Context(), deps, rec)
			cookie.ClearOn(w, cookie.InteractionProfile)
			cookie.ClearOn(w, cookie.CSRFProfile)
			emitAuthorizeError(w, r, deps, req, errAccessDenied, "request_uri is no longer valid")
			return
		}
		renderServerError(w, r, deps, "authorization completion unavailable", err)
		return
	}
	out, err := deps.Sessions.Establish(r.Context(), decodeCompletionSession(intent.Session))
	if err != nil {
		renderServerError(w, r, deps, "could not establish session", err)
		return
	}
	if out.Cookie != "" {
		if err := setSessionCookie(w, out.Cookie, intent.Session.ExpiresAt, deps.now()); err != nil {
			renderServerError(w, r, deps, "could not establish session", err)
			return
		}
	}
	deleteErr := deleteCompletionAnchor(r.Context(), deps, rec)
	if deleteErr != nil && !errors.Is(deleteErr, store.ErrNotFound) {
		renderServerError(w, r, deps, "could not finalize interaction", deleteErr)
		return
	}
	// The conditional-delete winner owns completion audit emission. This
	// remains true when a prior request committed the durable transaction but
	// failed during Session establishment or anchor deletion, and prevents
	// concurrent resumptions from emitting duplicates.
	if deleteErr == nil {
		emitCompletionAudit(r.Context(), deps, intent, req.ClientID, code.GrantID, out, consentAutoGranted(state))
	}
	cookie.ClearOn(w, cookie.InteractionProfile)
	cookie.ClearOn(w, cookie.CSRFProfile)
	emitAuthorizeSuccess(w, r, deps, req, code.ID)
}

// refreshCompletionSession applies the sliding-idle policy to the session
// that the persisted completion intent will leave current. Reuse emits the
// TouchAndReissue cookie directly because Establish(Reuse) intentionally has
// no cookie output. Chooser switching touches the selected sibling first and
// then lets Establish(Switch) issue its payload, with the updated expiry
// carried into the cookie Max-Age cap below. Issue/add-account/rotate create a
// fresh record and therefore do not touch the pre-interaction session.
func refreshCompletionSession(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	intent *authorize.CompletionIntent,
) error {
	switch sessions.EstablishMode(intent.Session.Mode) {
	case sessions.EstablishReuse:
		_, err := resolveSession(w, r, deps)
		return err
	case sessions.EstablishIssue, sessions.EstablishRotate, sessions.EstablishAddAccount:
		return nil
	case sessions.EstablishSwitch:
		record := decodeCompletionSession(intent.Session).Record
		active := &sessions.Active{
			Payload: sessions.Payload{
				ChooserGroupID:   record.ChooserGroupID,
				CurrentSessionID: record.ID,
			},
			Session: &record,
		}
		touch, err := deps.Sessions.TouchAndReissue(r.Context(), active)
		if err != nil {
			return err
		}
		intent.Session.ExpiresAt = touch.ExpiresAt
		intent.Session.UpdatedAt = touch.UpdatedAt
		return nil
	default:
		return fmt.Errorf("authorizeendpoint: unsupported completion establishment mode %q", intent.Session.Mode)
	}
}

func deleteCompletionAnchor(
	ctx context.Context,
	deps resolved,
	rec *store.Interaction,
) error {
	cas, err := interactionCAS(deps)
	if err != nil {
		return err
	}
	return cas.DeleteIfUnchanged(ctx, rec)
}

// ensureDurableCompletion produces the authorization code the terminal
// response carries, minting it inside one transaction with the grant
// amendment and the PAR consumption when it does not already exist.
//
// A lost optimistic-lock race is retried through [retryOnGrantConflict]
// rather than surfaced. The retry is safe because the whole body is keyed
// on the intent's stable code id and re-reads every record it amends: a
// rolled-back attempt wrote nothing, and an attempt whose commit landed
// is caught by the existing-code check at the top of
// [attemptDurableCompletion] rather than minting a second result.
func ensureDurableCompletion(
	ctx context.Context,
	deps resolved,
	req *authorize.Request,
	intent *authorize.CompletionIntent,
) (*store.AuthorizationCode, bool, error) {
	return retryOnGrantConflict(ctx, func() (*store.AuthorizationCode, bool, error) {
		return attemptDurableCompletion(ctx, deps, req, intent)
	})
}

func attemptDurableCompletion(
	ctx context.Context,
	deps resolved,
	req *authorize.Request,
	intent *authorize.CompletionIntent,
) (*store.AuthorizationCode, bool, error) {
	if existing, err := deps.Codes.Find(ctx, intent.CodeID); err == nil {
		if !authorizationCodeMatches(existing, req, completionCodeBinding(intent, req, ""), false) {
			return nil, false, errors.New("authorizeendpoint: stable authorization code collision")
		}
		return existing, false, nil
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, false, fmt.Errorf("authorizeendpoint: find stable authorization code: %w", err)
	}
	if deps.Transactions == nil {
		return nil, false, errors.New("authorizeendpoint: transactional store unavailable")
	}
	tx, err := deps.Transactions.BeginTx(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("authorizeendpoint: begin completion transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	txDeps := transactionalDeps(deps, tx)
	txDeps.Transactions = nil
	grant, err := upsertGrant(ctx, txDeps, grantUpsert{
		Subject:       intent.Subject,
		ClientID:      req.ClientID,
		Scope:         intent.GrantScope,
		DeclinedScope: intent.DeclinedScope,
		AuthTime:      intent.AuthTime,
		ACR:           intent.ACR,
		AMR:           intent.AMR,
		Claims:        req.Claims,
		// Scope comes from the ceremony's answer, authorization_details
		// from the request: the consent step has no element-level row to
		// answer with, so the elements are persisted as requested even
		// when the user approved no scope at all.
		AuthorizationDetails: req.AuthorizationDetails,
		GMAction:             req.GrantManagementAction,
		GMGrantID:            req.GrantID,
		NewGrantID:           intent.NewGrantID,
		Now:                  deps.now(),
	})
	if err != nil {
		return recoverCompletionAfterTxError(ctx, tx, deps, req, intent, err)
	}
	if err := consumePARIfNeeded(ctx, txDeps, req); err != nil {
		return recoverCompletionAfterTxError(ctx, tx, deps, req, intent, err)
	}
	now := deps.now().UTC()
	code := newAuthorizationCode(req, completionCodeBinding(intent, req, grant.ID), grant, now, deps.AuthCodeTTL)
	if err := txDeps.Codes.Save(ctx, code); err != nil {
		return recoverCompletionAfterTxError(
			ctx,
			tx,
			deps,
			req,
			intent,
			fmt.Errorf("authorizeendpoint: persist stable authorization code: %w", err),
		)
	}
	if err := tx.Commit(); err != nil {
		return recoverCompletionAfterTxError(
			ctx,
			tx,
			deps,
			req,
			intent,
			fmt.Errorf("authorizeendpoint: commit completion transaction: %w", err),
		)
	}
	return code, true, nil
}

func recoverCompletionAfterTxError(
	ctx context.Context,
	tx store.Tx,
	deps resolved,
	req *authorize.Request,
	intent *authorize.CompletionIntent,
	cause error,
) (*store.AuthorizationCode, bool, error) {
	// Release backend transaction locks before probing the outer store. This
	// also handles the race where another terminal POST committed the same
	// stable code while this transaction was waiting to begin.
	if err := tx.Rollback(); err != nil {
		return nil, false, errors.Join(cause, fmt.Errorf("rollback completion transaction: %w", err))
	}
	if existing, err := deps.Codes.Find(ctx, intent.CodeID); err == nil {
		if authorizationCodeMatches(existing, req, completionCodeBinding(intent, req, ""), false) {
			return existing, false, nil
		}
		return nil, false, errors.Join(
			cause,
			errors.New("authorizeendpoint: stable authorization code collision"),
		)
	} else if !errors.Is(err, store.ErrNotFound) {
		return nil, false, errors.Join(
			cause,
			fmt.Errorf("authorizeendpoint: recover stable authorization code: %w", err),
		)
	}
	return nil, false, cause
}

func completionCodeBinding(intent *authorize.CompletionIntent, req *authorize.Request, grantID string) codeBinding {
	return codeBinding{
		ID:       intent.CodeID,
		ClientID: req.ClientID,
		Subject:  intent.Subject,
		GrantID:  grantID,
		Scope:    slices.Clone(intent.GrantScope),
		AuthTime: intent.AuthTime,
		ACR:      intent.ACR,
		AMR:      slices.Clone(intent.AMR),
	}
}

// emitCompletionAudit writes the audit records the interactive exit owes:
// the session record when the interaction established one, the consent
// grant, and the authorization code the browser is about to carry away.
//
// The code.issued record is the counterpart of the one [mintAndRedirect]
// writes on the silent exit. Both exits emit it so an operator correlating
// code.issued against code.consumed sees a matching pair for every code the
// OP hands to an RP; a consumption with no issuance is then evidence of an
// injected or forged code rather than of a user who happened to pass through
// the consent screen. The extras carry the same keys with the same meaning
// on both exits: grant_id, the scope the code was minted with, and the
// fingerprinted code id.
func emitCompletionAudit(
	ctx context.Context,
	deps resolved,
	intent *authorize.CompletionIntent,
	clientID string,
	grantID string,
	out sessions.Outcome,
	autoGranted bool,
) {
	if out.Cookie != "" && intent.Session.Mode != string(sessions.EstablishReuse) {
		emitSessionCreated(ctx, deps, intent.Subject, out.SessionID, out.ChooserGroupID, intent.Session.Mode)
	}
	consentEvent, consentMessage := opAuditConsentGranted, "consent grant recorded"
	if autoGranted {
		consentEvent, consentMessage = opAuditConsentGrantedFirstParty, "first-party consent auto-granted"
	}
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:     consentEvent,
		Level:    audit.LevelInfo,
		Message:  consentMessage,
		ActorID:  intent.Subject,
		ClientID: clientID,
		Extras: map[string]any{
			"grant_id": grantID,
			"scope":    slices.Clone(intent.GrantScope),
			// intent.CodeID is the authorization code the browser is
			// about to carry to the RP, so only its irreversible
			// digest reaches the audit stream.
			"completion_id": audit.Fingerprint(intent.CodeID),
		},
	})
	emitCodeIssued(ctx, deps, intent.Subject, clientID, out.SessionID, intent.CodeID, grantID, intent.GrantScope)
}

// emitCodeIssued records an authorization code handed to the browser. The
// code is a bearer credential for its whole TTL, so only its irreversible
// digest reaches the audit stream; the token endpoint stamps the same key
// with the same transform, so the two records still correlate.
func emitCodeIssued(
	ctx context.Context,
	deps resolved,
	subject, clientID, sessionID, codeID, grantID string,
	scope []string,
) {
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:      opAuditCodeIssued,
		Level:     audit.LevelInfo,
		Message:   "authorization code issued",
		ActorID:   subject,
		ClientID:  clientID,
		SessionID: sessionID,
		Extras: map[string]any{
			"code_id":  audit.Fingerprint(codeID),
			"grant_id": grantID,
			"scope":    slices.Clone(scope),
		},
	})
}

// consentAutoGranted reports whether the completing chain's consent was
// the first-party auto-grant rather than a ceremony or a cached grant.
// The chain state was decoded to reach the terminal step, so a record
// that no longer decodes reports the ordinary consent event.
func consentAutoGranted(state authorize.RequestState) bool {
	st, err := decodeAuthnState(state.Authn)
	return err == nil && st.ConsentAutoGranted
}

func emitSessionCreated(ctx context.Context, deps resolved, subject, sessionID, chooserGroupID, reason string) {
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:      opAuditSessionCreated,
		Level:     audit.LevelInfo,
		Message:   "session created",
		ActorID:   subject,
		SessionID: sessionID,
		Extras: map[string]any{
			"chooser_group_id": chooserGroupID,
			"reason":           reason,
		},
	})
}
