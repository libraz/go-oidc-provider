package authorizeendpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// serveInteraction is the multiplexed entry point for /interaction/{uid}.
// It dispatches GET / POST / DELETE to the matching helper after pulling
// the UID out of the path and validating the cookie binding.
func serveInteraction(w http.ResponseWriter, r *http.Request, deps resolved) {
	uid := r.PathValue("uid")
	if uid == "" {
		http.NotFound(w, r)
		return
	}
	if !verifyInteractionCookie(r, deps, uid) {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		serveInteractionGet(w, r, deps, uid)
	case http.MethodPost:
		serveInteractionPost(w, r, deps, uid)
	case http.MethodDelete:
		serveInteractionDelete(w, r, deps, uid)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		renderJSONError(w, http.StatusMethodNotAllowed, errInvalidRequest, "method not allowed")
	}
}

// verifyInteractionCookie reports whether the __Host-oidc_interaction
// cookie carries a sealed UID matching the URL path UID. Mismatch (or
// absent / unsealable cookie) yields false; the caller MUST translate the
// negative outcome into a 404 so the endpoint cannot be used as an oracle
// for "this UID exists in the store".
func verifyInteractionCookie(r *http.Request, deps resolved, uid string) bool {
	c, err := r.Cookie(cookie.InteractionProfile.Name)
	if err != nil || c == nil || c.Value == "" {
		return false
	}
	raw, err := deps.CookieCodec.Open(c.Value, []byte(interactionAAD))
	if err != nil {
		return false
	}
	return string(raw) == uid
}

// serveInteractionGet drives the orchestrator one tick from the
// persisted state without any submission. The function is the SPA's
// entry point after the /authorize redirect: the first call advances
// the chain into [authn.PhaseAuthn] and renders the first prompt;
// subsequent reloads re-emit a fresh prompt with a new StateRef.
func serveInteractionGet(w http.ResponseWriter, r *http.Request, deps resolved, uid string) {
	rec, state, ok := loadInteraction(w, r, deps, uid)
	if !ok {
		return
	}
	authnState, err := decodeAuthnState(state.Authn)
	if err != nil {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "interaction state corrupted")
		return
	}
	dispatchTick(w, r, deps, rec, state, authnState, nil)
}

// serveInteractionPost runs the orchestrator against the SPA's
// submission and dispatches the resulting [interaction.Step].
func serveInteractionPost(w http.ResponseWriter, r *http.Request, deps resolved, uid string) {
	if err := csrf.CheckOrigin(r, deps.Origins); err != nil {
		renderJSONError(w, http.StatusForbidden, errInvalidRequest, "origin not allowed")
		return
	}
	if !verifyCSRFToken(w, r, deps, uid) {
		return
	}
	rec, state, ok := loadInteraction(w, r, deps, uid)
	if !ok {
		return
	}
	authnState, err := decodeAuthnState(state.Authn)
	if err != nil {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "interaction state corrupted")
		return
	}
	submission, err := deps.Driver.ParseSubmission(r)
	if err != nil {
		renderJSONError(w, http.StatusBadRequest, errInvalidRequest, "invalid interaction body")
		return
	}
	dispatchTick(w, r, deps, rec, state, authnState, &submission)
}

// serveInteractionDelete cancels the interaction. The function emits
// the access_denied redirect when a redirect target is available;
// otherwise it returns 204 so the SPA can treat the call as a
// best-effort cancel.
func serveInteractionDelete(w http.ResponseWriter, r *http.Request, deps resolved, uid string) {
	rec, state, ok := loadInteraction(w, r, deps, uid)
	if !ok {
		return
	}
	_ = deps.Interactions.Delete(r.Context(), rec.ID)
	clearCookie(w, cookie.InteractionProfile)
	clearCookie(w, cookie.CSRFProfile)
	stampNoStore(w)
	if state.Library.RedirectURI == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	emitAuthorizeError(w, r, deps, state.Library.ToRequest(), errAccessDenied, "user aborted the interaction")
}

// dispatchTick runs a single orchestrator tick and routes the
// resulting Step. The function consolidates the GET / POST branches
// so the SPA-visible behaviour stays identical regardless of whether
// the SPA polled for the next prompt or submitted a reply.
func dispatchTick(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	rec *store.Interaction,
	state authorize.RequestState,
	authnState authn.State,
	submission *interaction.FormSubmission,
) {
	now := deps.now().UTC()
	next, step, err := deps.Authn.Tick(r.Context(), authnState, authn.Input{
		Submission: submission,
		Now:        now,
	})
	if err != nil {
		writeAuthnError(w, r, deps, state, err)
		return
	}
	if step.Result != nil {
		terminateInteraction(w, r, deps, rec, state, next, *step.Result)
		return
	}
	if step.Prompt == nil {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "orchestrator returned empty step")
		return
	}
	if err := persistAuthnState(r.Context(), deps, rec, state, next, step.Prompt.Type, now); err != nil {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "could not persist interaction")
		return
	}
	token, err := deps.CSRF.Issue(rec.ID, now)
	if err != nil {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "could not issue csrf token")
		return
	}
	if err := setCSRFCookie(w, token, deps.InteractionTTL); err != nil {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "could not set csrf cookie")
		return
	}
	stampNoStore(w)
	if err := deps.Driver.Render(w, r, *step.Prompt); err != nil {
		// Render's own headers may already be partially written;
		// surfacing a JSON error after that is unsafe so we just
		// bail. The persistent state is consistent.
		return
	}
}

// writeAuthnError translates an orchestrator [authn] error into the
// matching HTTP response. Most failures are server-side (state
// corruption, store outage) but a few — invalid StateRef, risk denial
// — surface as 4xx.
func writeAuthnError(w http.ResponseWriter, r *http.Request, deps resolved, state authorize.RequestState, err error) {
	switch {
	case errors.Is(err, authn.ErrInvalidStateRef):
		renderJSONError(w, http.StatusForbidden, errInvalidRequest, "stateref rejected")
	case errors.Is(err, authn.ErrChainComplete):
		renderJSONError(w, http.StatusGone, errInvalidRequest, "interaction already complete")
	case errors.Is(err, authn.ErrRiskDenied):
		emitAuthorizeError(w, r, deps, state.Library.ToRequest(), errAccessDenied, "risk policy denied the request")
	default:
		renderJSONError(w, http.StatusInternalServerError, errServerError, "orchestrator failed")
	}
}

// persistAuthnState saves the updated record + encoded chain state
// back to the interaction store. The function centralises the
// encoding so the callers do not have to worry about the json /
// rec.Step / rec.UpdatedAt bookkeeping.
func persistAuthnState(
	ctx context.Context,
	deps resolved,
	rec *store.Interaction,
	state authorize.RequestState,
	next authn.State,
	step string,
	now time.Time,
) error {
	encoded, err := encodeAuthnState(next)
	if err != nil {
		return fmt.Errorf("authorizeendpoint: encode authn state: %w", err)
	}
	state.Authn = encoded
	raw, err := authorize.MarshalState(state)
	if err != nil {
		return fmt.Errorf("authorizeendpoint: marshal interaction state: %w", err)
	}
	rec.RawState = raw
	rec.Step = step
	rec.UpdatedAt = now
	if err := deps.Interactions.Save(ctx, rec); err != nil {
		return fmt.Errorf("authorizeendpoint: save interaction: %w", err)
	}
	return nil
}

// loadInteraction fetches the persisted record and decodes its state
// payload. On failure the handler emits the matching response and
// returns ok=false so the caller can stop.
func loadInteraction(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	uid string,
) (*store.Interaction, authorize.RequestState, bool) {
	rec, err := deps.Interactions.Find(r.Context(), uid)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return nil, authorize.RequestState{}, false
		}
		renderJSONError(w, http.StatusInternalServerError, errServerError, "interaction store unavailable")
		return nil, authorize.RequestState{}, false
	}
	state, err := authorize.UnmarshalState(rec.RawState)
	if err != nil {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "interaction state corrupted")
		return nil, authorize.RequestState{}, false
	}
	return rec, state, true
}

// verifyCSRFToken enforces the double-submit pattern. It returns true
// on success; on failure it has already written the response.
func verifyCSRFToken(w http.ResponseWriter, r *http.Request, deps resolved, uid string) bool {
	cookieVal, err := r.Cookie(cookie.CSRFProfile.Name)
	if err != nil || cookieVal == nil || cookieVal.Value == "" {
		renderJSONError(w, http.StatusForbidden, errInvalidRequest, "csrf cookie missing")
		return false
	}
	header := r.Header.Get("X-CSRF-Token")
	if header == "" {
		renderJSONError(w, http.StatusForbidden, errInvalidRequest, "csrf token missing")
		return false
	}
	if !csrf.ConstantTimeEqual(cookieVal.Value, header) {
		renderJSONError(w, http.StatusForbidden, errInvalidRequest, "csrf token mismatch")
		return false
	}
	if err := deps.CSRF.Verify(header, uid, deps.now(), deps.InteractionTTL); err != nil {
		renderJSONError(w, http.StatusForbidden, errInvalidRequest, "csrf token rejected")
		return false
	}
	return true
}

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
		_ = deps.Interactions.Delete(r.Context(), rec.ID)
		clearCookie(w, cookie.InteractionProfile)
		clearCookie(w, cookie.CSRFProfile)
		emitAuthorizeError(w, r, deps, req, errAccessDenied, "subject was not authenticated")
		return
	}
	acr, amr, _ := authn.Aggregate(authnState.Factors)
	if err := ensureSession(w, r, deps, result.Subject, result.AuthTime, amr, acr); err != nil {
		_ = deps.Interactions.Delete(r.Context(), rec.ID)
		clearCookie(w, cookie.InteractionProfile)
		clearCookie(w, cookie.CSRFProfile)
		emitAuthorizeError(w, r, deps, req, errServerError, "could not establish session")
		return
	}
	grantScope := chooseGrantScope(result.Scope, req.Scope)
	grant, err := upsertGrant(r.Context(), deps, result.Subject, rec.ClientID, grantScope, deps.now())
	if err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not record grant")
		return
	}
	codeID, err := newRandomB64(codeByteLength)
	if err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not allocate code")
		return
	}
	now := deps.now().UTC()
	authCode := &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            rec.ClientID,
		Subject:             result.Subject,
		GrantID:             grant.ID,
		RedirectURI:         req.RedirectURI,
		Scope:               append([]string(nil), grantScope...),
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
		State:               req.State,
		ExpiresAt:           now.Add(deps.AuthCodeTTL),
		CreatedAt:           now,
	}
	if err := deps.Codes.Save(r.Context(), authCode); err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not persist authorization code")
		return
	}
	_ = deps.Interactions.Delete(r.Context(), rec.ID)
	clearCookie(w, cookie.InteractionProfile)
	clearCookie(w, cookie.CSRFProfile)
	emitAuthorizeSuccess(w, r, deps, req, codeID)
}

// ensureSession reuses the cookie-bound session when it represents
// the same subject, or issues a fresh one. The freshly issued cookie
// is set on the response writer.
func ensureSession(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	subject string,
	authTime time.Time,
	amr []string,
	acr string,
) error {
	active, err := resolveSession(r, deps)
	if err == nil && active != nil && active.Session != nil && active.Session.Subject == subject {
		return nil
	}
	out, err := deps.Sessions.Issue(r.Context(), sessions.Login{
		Subject:  subject,
		AuthTime: authTime,
		AMR:      slices.Clone(amr),
		ACR:      acr,
	})
	if err != nil {
		return fmt.Errorf("authorizeendpoint: issue session: %w", err)
	}
	c, err := cookie.Build(cookie.SessionProfile, out.Cookie)
	if err != nil {
		return fmt.Errorf("authorizeendpoint: build session cookie: %w", err)
	}
	http.SetCookie(w, c)
	return nil
}

// chooseGrantScope picks the scope slice the authorize-code mint
// records into the grant and the authorization code. The orchestrator
// stamps the consent-approved subset on
// [interaction.Result.Scope]; when present it wins, otherwise the
// helper falls back to the original request scope. The fallback
// preserves backward-compatible behaviour for chains that skip the
// built-in consent screen (existing grant covered, or the embedder
// suppressed consent).
func chooseGrantScope(approved, requested []string) []string {
	if len(approved) > 0 {
		return append([]string(nil), approved...)
	}
	return append([]string(nil), requested...)
}

// upsertGrant ensures a grant exists for (subject, clientID) covering
// at least the supplied scope. Returns the persisted grant.
func upsertGrant(
	ctx context.Context,
	deps resolved,
	subject, clientID string,
	scope []string,
	now time.Time,
) (*store.Grant, error) {
	existing, err := deps.Grants.FindBySubjectClient(ctx, subject, clientID)
	if err == nil && existing != nil && scopeIsSubset(scope, existing.Scope) {
		existing.UpdatedAt = now.UTC()
		if err := deps.Grants.Save(ctx, existing); err != nil {
			return nil, fmt.Errorf("authorizeendpoint: refresh grant: %w", err)
		}
		return existing, nil
	}
	grantID, err := newRandomB64(uidByteLength)
	if err != nil {
		return nil, err
	}
	g := &store.Grant{
		ID:        grantID,
		Subject:   subject,
		ClientID:  clientID,
		Scope:     append([]string(nil), scope...),
		CreatedAt: now.UTC(),
		UpdatedAt: now.UTC(),
	}
	if err := deps.Grants.Save(ctx, g); err != nil {
		return nil, fmt.Errorf("authorizeendpoint: persist grant: %w", err)
	}
	return g, nil
}

// setCSRFCookie writes the __Host-oidc_csrf cookie carrying token.
func setCSRFCookie(w http.ResponseWriter, token string, _ time.Duration) error {
	c, err := cookie.Build(cookie.CSRFProfile, token)
	if err != nil {
		return fmt.Errorf("authorizeendpoint: build csrf cookie: %w", err)
	}
	http.SetCookie(w, c)
	return nil
}

// decodeAuthnState parses the chain state from the persisted blob.
// An empty blob produces the zero [authn.State], which the
// orchestrator treats as a freshly-initialised attempt.
func decodeAuthnState(raw json.RawMessage) (authn.State, error) {
	if len(raw) == 0 {
		return authn.State{ActiveFactorIdx: -1, Phase: authn.PhaseBeforeAuthn}, nil
	}
	var s authn.State
	if err := json.Unmarshal(raw, &s); err != nil {
		return authn.State{}, fmt.Errorf("authorizeendpoint: decode authn state: %w", err)
	}
	return s, nil
}

// encodeAuthnState marshals the chain state for persistence.
func encodeAuthnState(s authn.State) (json.RawMessage, error) {
	out, err := json.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("authorizeendpoint: encode authn state: %w", err)
	}
	return out, nil
}
