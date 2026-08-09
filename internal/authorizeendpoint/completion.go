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
	"time"

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
	acr string,
	amr []string,
	grantScope []string,
) (*authorize.CompletionIntent, error) {
	if len(deps.CompletionKey) < 32 {
		return nil, errors.New("authorizeendpoint: completion key unavailable")
	}
	active, err := resolveSession(r, deps)
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
			AMR:      slices.Clone(amr),
			ACR:      acr,
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
		ACR:        acr,
		AMR:        slices.Clone(amr),
		GrantScope: slices.Clone(grantScope),
		Session:    encodeCompletionSession(establishment),
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
			"authorizeendpoint: marshal completion intent: %w", err)
	}
	cas, ok := deps.Interactions.(store.InteractionStoreCAS)
	if !ok {
		return nil, authorize.RequestState{}, errors.New(
			"authorizeendpoint: interaction store lacks compare-and-swap")
	}
	next := *rec
	next.RawState = raw
	next.UpdatedAt = deps.now().UTC()
	if err := cas.CompareAndSwap(ctx, rec, &next); err == nil {
		return &next, state, nil
	} else if !errors.Is(err, store.ErrConflict) {
		return nil, authorize.RequestState{}, fmt.Errorf(
			"authorizeendpoint: persist completion intent: %w", err)
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
			"authorizeendpoint: reload completion intent after conflict: %w", err)
	}
	currentState, err := authorize.UnmarshalState(current.RawState)
	if err != nil {
		return nil, authorize.RequestState{}, fmt.Errorf(
			"authorizeendpoint: decode completion intent after conflict: %w", err)
	}
	if currentState.Completion == nil ||
		currentState.Completion.Version != completionIntentVersion {
		return nil, authorize.RequestState{}, errors.New(
			"authorizeendpoint: interaction changed before completion intent claim")
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
		renderJSONError(w, http.StatusInternalServerError, errServerError, "authorization completion intent is invalid")
		return
	}
	req := state.Library.ToRequest()
	code, _, err := ensureDurableCompletion(r.Context(), deps, req, intent)
	if err != nil {
		if errors.Is(err, errGrantNotOwned) {
			_ = deleteCompletionAnchor(r.Context(), deps, rec)
			clearCookie(w, cookie.InteractionProfile)
			clearCookie(w, cookie.CSRFProfile)
			emitAuthorizeError(w, r, deps, req, errInvalidGrant, "grant_id is not owned by this subject/client")
			return
		}
		if errors.Is(err, store.ErrAlreadyConsumed) {
			_ = deleteCompletionAnchor(r.Context(), deps, rec)
			clearCookie(w, cookie.InteractionProfile)
			clearCookie(w, cookie.CSRFProfile)
			emitAuthorizeError(w, r, deps, req, errAccessDenied, "request_uri is no longer valid")
			return
		}
		renderJSONError(w, http.StatusInternalServerError, errServerError, "authorization completion unavailable")
		return
	}
	out, err := deps.Sessions.Establish(r.Context(), decodeCompletionSession(intent.Session))
	if err != nil {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "could not establish session")
		return
	}
	if out.Cookie != "" {
		if err := setSessionCookie(w, out.Cookie); err != nil {
			renderJSONError(w, http.StatusInternalServerError, errServerError, "could not establish session")
			return
		}
	}
	deleteErr := deleteCompletionAnchor(r.Context(), deps, rec)
	if deleteErr != nil && !errors.Is(deleteErr, store.ErrNotFound) {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "could not finalize interaction")
		return
	}
	// The conditional-delete winner owns completion audit emission. This
	// remains true when a prior request committed the durable transaction but
	// failed during Session establishment or anchor deletion, and prevents
	// concurrent resumptions from emitting duplicates.
	if deleteErr == nil {
		emitCompletionAudit(r.Context(), deps, intent, req.ClientID, code.GrantID, out)
	}
	clearCookie(w, cookie.InteractionProfile)
	clearCookie(w, cookie.CSRFProfile)
	emitAuthorizeSuccess(w, r, deps, req, code.ID)
}

func deleteCompletionAnchor(
	ctx context.Context,
	deps resolved,
	rec *store.Interaction,
) error {
	cas, ok := deps.Interactions.(store.InteractionStoreCAS)
	if !ok {
		return errors.New("authorizeendpoint: interaction store lacks compare-and-swap")
	}
	return cas.DeleteIfUnchanged(ctx, rec)
}

func ensureDurableCompletion(
	ctx context.Context,
	deps resolved,
	req *authorize.Request,
	intent *authorize.CompletionIntent,
) (*store.AuthorizationCode, bool, error) {
	if existing, err := deps.Codes.Find(ctx, intent.CodeID); err == nil {
		if !completionCodeMatches(existing, req, intent) {
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
	txDeps := deps
	txDeps.Transactions = nil
	txDeps.Codes = tx.AuthorizationCodes()
	txDeps.Grants = tx.Grants()
	txDeps.PARs = tx.PushedAuthRequests()
	grant, err := upsertGrant(ctx, txDeps, grantUpsert{
		Subject:              intent.Subject,
		ClientID:             req.ClientID,
		Scope:                intent.GrantScope,
		AuthTime:             intent.AuthTime,
		ACR:                  intent.ACR,
		AMR:                  intent.AMR,
		Claims:               req.Claims,
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
	code := completionAuthorizationCode(req, intent, grant.ID, now, deps.AuthCodeTTL)
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
		if completionCodeMatches(existing, req, intent) {
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

func completionAuthorizationCode(
	req *authorize.Request,
	intent *authorize.CompletionIntent,
	grantID string,
	now time.Time,
	ttl time.Duration,
) *store.AuthorizationCode {
	return &store.AuthorizationCode{
		ID:                  intent.CodeID,
		ClientID:            req.ClientID,
		Subject:             intent.Subject,
		GrantID:             grantID,
		RedirectURI:         req.RedirectURI,
		Scope:               slices.Clone(intent.GrantScope),
		Resource:            req.Resource,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
		State:               req.State,
		DPoPJKT:             req.DPoPJKT,
		ExpiresAt:           now.Add(ttl),
		CreatedAt:           now,
	}
}

func completionCodeMatches(
	code *store.AuthorizationCode,
	req *authorize.Request,
	intent *authorize.CompletionIntent,
) bool {
	if code == nil {
		return false
	}
	return code.ID == intent.CodeID &&
		code.ClientID == req.ClientID &&
		code.Subject == intent.Subject &&
		code.RedirectURI == req.RedirectURI &&
		slices.Equal(code.Scope, intent.GrantScope) &&
		code.Resource == req.Resource &&
		code.CodeChallenge == req.CodeChallenge &&
		code.CodeChallengeMethod == req.CodeChallengeMethod &&
		code.Nonce == req.Nonce &&
		code.State == req.State &&
		code.DPoPJKT == req.DPoPJKT
}

func emitCompletionAudit(
	ctx context.Context,
	deps resolved,
	intent *authorize.CompletionIntent,
	clientID string,
	grantID string,
	out sessions.Outcome,
) {
	if out.Cookie != "" && intent.Session.Mode != string(sessions.EstablishReuse) {
		emitSessionCreated(ctx, deps, intent.Subject, out.SessionID, out.ChooserGroupID, intent.Session.Mode)
	}
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:     opAuditConsentGranted,
		Level:    audit.LevelInfo,
		Message:  "consent grant recorded",
		ActorID:  intent.Subject,
		ClientID: clientID,
		Extras: map[string]any{
			"grant_id":      grantID,
			"scope":         slices.Clone(intent.GrantScope),
			"completion_id": intent.CodeID,
		},
	})
}
