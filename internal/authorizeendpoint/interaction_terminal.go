package authorizeendpoint

import (
	"errors"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/consent"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// terminateInteraction is the happy-path branch of a Tick that
// returned [interaction.Step.Result]. It mints a session for the
// bound subject, records / refreshes the grant for the requested
// scope, persists an authorization code, and emits the success
// redirect to the RP.
func terminateInteraction(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	rec *store.Interaction,
	state authorize.RequestState,
	authnState authn.State,
	result interaction.Result,
) {
	req := state.Library.ToRequest()
	if result.Subject == "" {
		if !claimTerminalInteraction(w, r, deps, rec) {
			return
		}
		cookie.ClearOn(w, cookie.InteractionProfile)
		cookie.ClearOn(w, cookie.CSRFProfile)
		emitAuthorizeError(w, r, deps, req, errAccessDenied, "subject was not authenticated")
		return
	}
	exit, backing := interactionExit(r, deps, authnState, result.Subject, result.AuthTime)
	decision := resolveScopeDecision(authnState, result, req.Scope)
	authCtx, err := validateTerminalAuthorization(r.Context(), deps, req, terminalAuthorization{
		Exit:                   exit,
		Backing:                backing,
		Subject:                result.Subject,
		Scope:                  decision.grantScope(req.Scope),
		ConsentAnswered:        decision.answered,
		ConsentFromCachedGrant: authnState.InteractionsRun[consent.Name] && !authnState.ConsentAutoGranted,
	})
	if err != nil {
		failTerminalAuthorization(w, r, deps, rec, req, err)
		return
	}
	var reported grantAuthContext
	if exit.spec().ServesEstablishedSession {
		reported, err = reportSessionAuthContext(r.Context(), r, deps, req, result.Subject, authnState, authCtx)
	} else {
		completed := deps.Authn.AuthContext(authnState).CompletedKinds
		reported, err = reportAuthContext(r.Context(), r, deps, req, result.Subject, authnState, completed, authCtx)
	}
	if err != nil {
		failTerminalAuthorization(w, r, deps, rec, req, err)
		return
	}
	// The completion carries the authentication the gate validated. A
	// session that records no auth_time leaves the ceremony's own reading
	// in place rather than reporting the zero instant.
	if !authCtx.AuthTime.IsZero() {
		result.AuthTime = authCtx.AuthTime
	}
	intent, err := prepareCompletionIntent(
		r,
		deps,
		rec,
		authnState,
		result,
		authCtx,
		reported,
		decision,
		req.Scope,
	)
	if err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not prepare authorization completion")
		return
	}
	rec, state, err = persistCompletionIntent(r.Context(), deps, rec, state, intent)
	if err != nil {
		renderServerError(w, r, deps, "could not persist authorization completion", err)
		return
	}
	resumeInteractionCompletion(w, r, deps, rec, state)
}

// failTerminalAuthorization ends a completed interaction whose result
// may not be turned into an authorization code, mapping the refusal onto
// the wire.
//
// Every refusal that names a permanent condition goes through
// [failTerminalInteraction], which claims the record and clears the
// ceremony cookies before answering: the ceremony is over either way,
// and leaving a completed record behind would let the browser replay the
// same chain straight back into the same refusal, with a manual record
// deletion as the only way out. Only a genuinely transient failure — a
// session store that could not answer — leaves the record in place, so a
// retry has something to succeed against.
func failTerminalAuthorization(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	rec *store.Interaction,
	req *authorize.Request,
	err error,
) {
	code, description, permanent := terminalRefusal(err)
	if !permanent {
		emitAuthorizeError(w, r, deps, req, code, description)
		return
	}
	failTerminalInteraction(w, r, deps, rec, req, code, description)
}

// failTerminalInteraction claims the interaction record, clears the
// ceremony cookies and emits code as a redirect error. Every
// "the ceremony finished but its result may not be turned into an
// authorization code" branch goes through here so none of them can
// leave a replayable completed record behind.
func failTerminalInteraction(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	rec *store.Interaction,
	req *authorize.Request,
	code, description string,
) {
	if !claimTerminalInteraction(w, r, deps, rec) {
		return
	}
	cookie.ClearOn(w, cookie.InteractionProfile)
	cookie.ClearOn(w, cookie.CSRFProfile)
	emitAuthorizeError(w, r, deps, req, code, description)
}

func claimTerminalInteraction(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	rec *store.Interaction,
) bool {
	cas, err := interactionCAS(deps)
	if err != nil {
		renderServerError(w, r, deps, err.Error(), err)
		return false
	}
	if err := cas.DeleteIfUnchanged(r.Context(), rec); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			renderBrowserError(w, r, deps.Driver, http.StatusGone, errInvalidRequest, "interaction already complete", "")
			return false
		}
		if errors.Is(err, store.ErrConflict) {
			current, state, loaded := loadInteraction(w, r, deps, rec.ID)
			if !loaded {
				return false
			}
			if state.Completion != nil {
				resumeInteractionCompletion(w, r, deps, current, state)
				return false
			}
			renderBrowserError(w, r, deps.Driver, http.StatusConflict, errInvalidRequest, "interaction changed; reload before continuing", "")
			return false
		}
		renderServerError(w, r, deps, "could not claim interaction", err)
		return false
	}
	return true
}
