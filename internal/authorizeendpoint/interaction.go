package authorizeendpoint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// csrfFormMaxBytes is the body-size cap [csrfFromForm] applies before
// calling [http.Request.ParseForm]. The cap matches the size a typical
// HTML driver allocates for [interaction.FormSubmission] bodies and is
// well above any legitimate CSRF token; the bound exists so a hostile
// client cannot stream an unbounded body through the verifier.
const csrfFormMaxBytes = 32 * 1024

// serveInteraction is the multiplexed entry point for /interaction/{uid}.
// It dispatches GET / POST / DELETE to the matching helper after pulling
// the UID out of the path and validating the cookie binding.
func serveInteraction(w http.ResponseWriter, r *http.Request, deps resolved) {
	// Stamp the ceremony hardening headers before any branch can write,
	// so every response this endpoint produces carries them regardless
	// of which Driver renders the body. See stampCeremonyHeaders.
	stampCeremonyHeaders(w)
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
		renderBrowserError(w, r, deps.Driver, http.StatusMethodNotAllowed, errInvalidRequest, "method not allowed", "")
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
	if state.Completion != nil {
		resumeInteractionCompletion(w, r, deps, rec, state)
		return
	}
	authnState, err := decodeAuthnState(state.Authn)
	if err != nil {
		// A chain state this build cannot read restarts like an expired one.
		http.NotFound(w, r)
		return
	}
	dispatchTick(w, r, deps, rec, state, authnState, nil)
}

// admitInteractionWrite gates a state-changing request on an interaction:
// origin check, record load and CSRF verification. An interaction whose
// completion is already pending resumes it here and reports ok=false, as
// does any refusal; the response is written in every ok=false case.
func admitInteractionWrite(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	uid string,
) (*store.Interaction, authorize.RequestState, bool) {
	if err := csrf.CheckOrigin(r, deps.InteractionOrigins); err != nil {
		if deps.OnOpaqueOrigin != nil && csrf.IsOpaqueSameOrigin(r) {
			deps.OnOpaqueOrigin()
		}
		renderBrowserError(w, r, deps.Driver, http.StatusForbidden, errInvalidRequest, "origin not allowed", "")
		return nil, authorize.RequestState{}, false
	}
	rec, state, ok := loadInteraction(w, r, deps, uid)
	if !ok {
		return nil, authorize.RequestState{}, false
	}
	if !verifyCSRFToken(w, r, deps, uid, rec.Step) {
		return nil, authorize.RequestState{}, false
	}
	if state.Completion != nil {
		resumeInteractionCompletion(w, r, deps, rec, state)
		return nil, authorize.RequestState{}, false
	}
	return rec, state, true
}

// serveInteractionPost runs the orchestrator against the SPA's
// submission and dispatches the resulting [interaction.Step].
func serveInteractionPost(w http.ResponseWriter, r *http.Request, deps resolved, uid string) {
	rec, state, ok := admitInteractionWrite(w, r, deps, uid)
	if !ok {
		return
	}
	authnState, err := decodeAuthnState(state.Authn)
	if err != nil {
		// A chain state this build cannot read restarts like an expired one.
		http.NotFound(w, r)
		return
	}
	submission, err := deps.Driver.ParseSubmission(r)
	if err != nil {
		renderBrowserError(w, r, deps.Driver, http.StatusBadRequest, errInvalidRequest, "invalid interaction body", "")
		return
	}
	dispatchTick(w, r, deps, rec, state, authnState, &submission)
}

// serveInteractionDelete cancels the interaction. The function emits
// the access_denied redirect when a redirect target is available;
// otherwise it returns 204 so the SPA can treat the call as a
// best-effort cancel.
//
//nolint:gocognit // The validation and conflict branches preserve the protocol's response distinctions.
func serveInteractionDelete(w http.ResponseWriter, r *http.Request, deps resolved, uid string) {
	rec, state, ok := admitInteractionWrite(w, r, deps, uid)
	if !ok {
		return
	}
	cas, err := interactionCAS(deps)
	if err != nil {
		renderServerError(w, r, deps, err.Error(), err)
		return
	}
	if err := cas.DeleteIfUnchanged(r.Context(), rec); err != nil {
		if errors.Is(err, store.ErrConflict) {
			current, currentState, loaded := loadInteraction(w, r, deps, uid)
			if !loaded {
				return
			}
			if currentState.Completion != nil {
				resumeInteractionCompletion(w, r, deps, current, currentState)
				return
			}
			renderBrowserError(w, r, deps.Driver, http.StatusConflict, errInvalidRequest, "interaction changed; reload before cancelling", "")
			return
		}
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		renderServerError(w, r, deps, "could not cancel interaction", err)
		return
	}
	clearCookie(w, cookie.InteractionProfile)
	clearCookie(w, cookie.CSRFProfile)
	httpx.StampNoStore(w)
	if state.Library.RedirectURI == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	emitAuthorizeError(w, r, deps, state.Library.ToRequest(), errAccessDenied, "user aborted the interaction")
}

// renderPersistFailure answers a dispatchTick whose interaction save
// failed: a concurrent completion is resumed, any other conflict asks
// for a reload, and a retired record is a 404.
func renderPersistFailure(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	savedRec *store.Interaction,
	savedState authorize.RequestState,
	err error,
) {
	switch {
	case errors.Is(err, store.ErrConflict) && savedState.Completion != nil:
		resumeInteractionCompletion(w, r, deps, savedRec, savedState)
	case errors.Is(err, store.ErrConflict):
		renderBrowserError(w, r, deps.Driver, http.StatusConflict, errInvalidRequest, "interaction changed; reload before continuing", "")
	case errors.Is(err, store.ErrNotFound):
		http.NotFound(w, r)
	default:
		renderServerError(w, r, deps, "could not persist interaction", err)
	}
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
	if err == nil && chooserJustBound(authnState, next) {
		next, step, err = reauthenticateChooserPick(r, deps, state, next, step, now)
	}
	if err != nil {
		failTick(w, r, deps, rec, state, next, now, err)
		return
	}
	if step.Result != nil {
		terminateInteraction(w, r, deps, rec, state, next, *step.Result)
		return
	}
	if step.Prompt == nil {
		renderBrowserError(w, r, deps.Driver, http.StatusInternalServerError, errServerError, "orchestrator returned empty step", "")
		return
	}
	savedRec, savedState, err := persistAuthnState(
		r.Context(),
		deps,
		rec,
		state,
		next,
		step.Prompt.Type,
		now,
	)
	if err != nil {
		renderPersistFailure(w, r, deps, savedRec, savedState, err)
		return
	}
	rec = savedRec
	state = savedState
	// Scope the CSRF token by the active prompt type so a token issued
	// for one step (e.g. "auth.password") cannot be replayed against a
	// later step (e.g. "auth.totp" or "consent.scope") inside the same
	// interaction. Without the scope binding the prior token stays
	// valid until the InteractionTTL window elapses, leaving a replay
	// vector inside a chain whose user-visible step changed.
	token, err := deps.CSRF.IssueScoped(rec.ID, step.Prompt.Type, now)
	if err != nil {
		renderServerError(w, r, deps, "could not issue csrf token", err)
		return
	}
	if err := setCSRFCookie(w, token); err != nil {
		renderServerError(w, r, deps, "could not set csrf cookie", err)
		return
	}
	httpx.StampNoStore(w)
	prompt := *step.Prompt
	// Stamp the CSRF token onto the prompt envelope so a server-
	// rendered Driver can embed it as a hidden form field. SPA
	// drivers that prefer the X-CSRF-Token header may ignore the
	// field; the POST handler accepts both routes, so the choice is
	// the driver's.
	prompt.CSRFToken = token
	if err := stampChooserAddAccountURL(deps, &prompt, next, state); err != nil {
		renderServerError(w, r, deps, "could not build chooser add-account URL", err)
		return
	}
	stampPromptLocale(r, deps, &prompt, next, state)
	renderPrompt(w, r, deps, rec.ClientID, prompt)
}

// failTick completes an errored tick: persist whatever the failure
// branch already mutated, then render the orchestrator's error. The
// persist has to happen first — it is what retires an in-flight
// challenge — and it writes its own response when it cannot land, in
// which case the authn error is not rendered at all.
func failTick(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	rec *store.Interaction,
	state authorize.RequestState,
	next authn.State,
	now time.Time,
	tickErr error,
) {
	if !persistFailedTick(w, r, deps, rec, state, next, now) {
		return
	}
	writeAuthnError(w, r, deps, state, tickErr)
}

// persistFailedTick saves the chain state an errored
// [authn.Orchestrator.Tick] returned. Tick's contract is that the
// updated [authn.State] comes back even on the error path, because the
// failure branches mutate it before giving up: the hard-failure branch
// clears the active factor's scratch, which is what retires an
// in-flight WebAuthn challenge, and the captcha branch advances its
// failure counter. Dropping that write would leave the same challenge
// replayable for the rest of the interaction's lifetime — and an
// authenticator with no signature counter (a platform passkey) has no
// second line of defence against the replay.
//
// The save is skipped when the tick left the state byte-identical (a
// rejected StateRef, say) so a hostile client cannot turn refused
// submissions into an unbounded stream of store writes. The persisted
// [store.Interaction.Step] is carried over unchanged: no new prompt was
// emitted, so the CSRF token already issued for the current step stays
// the valid one.
//
// It returns false once it has written a response of its own. A save
// that does not land is fail-closed: the caller is about to tell the
// client the attempt failed, and answering that way while the store
// still holds the state that made the attempt replayable is exactly the
// outcome the write exists to prevent.
func persistFailedTick(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	rec *store.Interaction,
	state authorize.RequestState,
	next authn.State,
	now time.Time,
) bool {
	encoded, err := encodeAuthnState(next)
	if err != nil {
		renderServerError(w, r, deps, "interaction state corrupted", err)
		return false
	}
	if bytes.Equal(encoded, state.Authn) {
		return true
	}
	savedRec, savedState, err := persistAuthnState(r.Context(), deps, rec, state, next, rec.Step, now)
	if err == nil {
		return true
	}
	renderPersistFailure(w, r, deps, savedRec, savedState, err)
	return false
}

// writeAuthnError translates an orchestrator [authn] error into the
// matching HTTP response. It is the one table from authn error class to
// wire response: every authn sentinel is either one of the cases below,
// or wraps [authn.ErrFactorAbort], or is a server fault (store outage,
// state corruption, mis-wiring) and takes the 500 fallback. The
// classification of each sentinel is pinned by
// TestAuthnSentinels_Classified.
func writeAuthnError(w http.ResponseWriter, r *http.Request, deps resolved, state authorize.RequestState, err error) {
	switch {
	case errors.Is(err, authn.ErrInvalidStateRef):
		renderBrowserError(w, r, deps.Driver, http.StatusForbidden, errInvalidRequest, "stateref rejected", "")
	case errors.Is(err, authn.ErrChainComplete):
		renderBrowserError(w, r, deps.Driver, http.StatusGone, errInvalidRequest, "interaction already complete", "")
	case errors.Is(err, authn.ErrRiskDenied):
		emitAuthorizeError(w, r, deps, state.Library.ToRequest(), errAccessDenied, "risk policy denied the request")
	case errors.Is(err, authn.ErrFactorAbort):
		// A terminal, user-input-driven failure: a factor that cannot
		// continue, or a submission the chain refused. Render as a 4xx so
		// the SPA / driver can tell it from a real server fault.
		renderBrowserError(w, r, deps.Driver, http.StatusBadRequest, errInvalidRequest, "authentication factor cannot continue", "")
	default:
		renderServerError(w, r, deps, "orchestrator failed", err)
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
) (*store.Interaction, authorize.RequestState, error) {
	encoded, err := encodeAuthnState(next)
	if err != nil {
		return nil, authorize.RequestState{}, fmt.Errorf(
			"authorizeendpoint: encode authn state: %w", err,
		)
	}
	state.Authn = encoded
	raw, err := authorize.MarshalState(state)
	if err != nil {
		return nil, authorize.RequestState{}, fmt.Errorf(
			"authorizeendpoint: marshal interaction state: %w", err,
		)
	}
	cas, err := interactionCAS(deps)
	if err != nil {
		return nil, authorize.RequestState{}, err
	}
	nextRec := *rec
	nextRec.RawState = raw
	nextRec.Step = step
	nextRec.UpdatedAt = now
	if err := cas.CompareAndSwap(ctx, rec, &nextRec); err == nil {
		return &nextRec, state, nil
	} else if !errors.Is(err, store.ErrConflict) {
		return nil, authorize.RequestState{}, fmt.Errorf(
			"authorizeendpoint: save interaction: %w", err,
		)
	}
	current, err := deps.Interactions.Find(ctx, rec.ID)
	if err == nil && current == nil {
		// A nil record alongside a nil error violates the store contract;
		// the concurrent writer's state cannot be read without it.
		err = store.ErrNotFound
	}
	if err != nil {
		return nil, authorize.RequestState{}, err
	}
	currentState, err := authorize.UnmarshalState(current.RawState)
	if err != nil {
		return nil, authorize.RequestState{}, fmt.Errorf(
			"authorizeendpoint: decode concurrent interaction state: %w", err,
		)
	}
	return current, currentState, store.ErrConflict
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
	if err == nil && rec == nil {
		// A nil record alongside a nil error violates the store contract;
		// an interaction the backend cannot produce is treated as absent.
		err = store.ErrNotFound
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return nil, authorize.RequestState{}, false
		}
		renderServerError(w, r, deps, "interaction store unavailable", err)
		return nil, authorize.RequestState{}, false
	}
	state, err := authorize.UnmarshalState(rec.RawState)
	if err != nil {
		renderServerError(w, r, deps, "interaction state corrupted", err)
		return nil, authorize.RequestState{}, false
	}
	return rec, state, true
}

// verifyCSRFToken enforces the double-submit pattern. It returns true
// on success; on failure it has already written the response.
//
// The submitted token is taken from the X-CSRF-Token header (the SPA
// pattern, where a JS client reads the prompt envelope and stamps the
// header) and falls back to the "csrf_token" form field when the
// request body is form-encoded (the SSR pattern, where a static HTML
// form posts the value as a hidden field). Either path satisfies the
// double-submit check; embedders pick whichever matches their UI
// architecture.
//
// scope is the active step name (the persisted [store.Interaction.Step]
// value, which equals the prompt type stamped at issuance). The
// per-step scope is folded into the HMAC binding so a token minted for
// one prompt (e.g. "auth.password") cannot be replayed against a later
// prompt in the same chain (e.g. "auth.totp" or "consent.scope") even
// when both share the same uid + cookie.
func verifyCSRFToken(w http.ResponseWriter, r *http.Request, deps resolved, uid, scope string) bool {
	cookieVal, err := r.Cookie(cookie.CSRFProfile.Name)
	if err != nil || cookieVal == nil || cookieVal.Value == "" {
		renderBrowserError(w, r, deps.Driver, http.StatusForbidden, errInvalidRequest, "csrf cookie missing", "")
		return false
	}
	submitted := r.Header.Get(csrf.HeaderName)
	if submitted == "" {
		submitted = csrfFromForm(r)
	}
	if submitted == "" {
		renderBrowserError(w, r, deps.Driver, http.StatusForbidden, errInvalidRequest, "csrf token missing", "")
		return false
	}
	if !csrf.ConstantTimeEqual(cookieVal.Value, submitted) {
		renderBrowserError(w, r, deps.Driver, http.StatusForbidden, errInvalidRequest, "csrf token mismatch", "")
		return false
	}
	if err := deps.CSRF.VerifyScoped(submitted, uid, scope, deps.now(), deps.InteractionTTL); err != nil {
		renderBrowserError(w, r, deps.Driver, http.StatusForbidden, errInvalidRequest, "csrf token rejected", "")
		return false
	}
	return true
}

// csrfFromForm reads the "csrf_token" field from a url-encoded body.
// It returns "" when the body is not form-encoded so the caller falls
// through to the missing-token branch and JSON-mode SPAs keep their
// header-only contract.
//
// The media-type test goes through the same [isFormContent] predicate
// the rest of the package uses, which matches the type/subtype
// case-insensitively per RFC 9110 §8.3 and tolerates parameters. The
// set of bodies this function will look for a token in has to be a
// superset of the set the configured Driver accepts as a form
// submission — [interaction.HTMLDriver] applies the same
// case-insensitive rule — or the stricter predicate silently answers
// 403 to a submission the Driver would have parsed.
//
// The function caps the body through [http.MaxBytesReader] before
// calling [http.Request.ParseForm] so a hostile client cannot stream
// an unbounded body. The parse drains r.Body, which is the
// precondition [interaction.Driver.ParseSubmission] documents for
// form-encoded bodies: an implementation that accepts them reads the
// fields from r.PostForm, or calls ParseForm itself and gets the
// standard library's cached parse.
func csrfFromForm(r *http.Request) string {
	if !endpointsupport.IsFormContent(r.Header.Get("Content-Type")) {
		return ""
	}
	r.Body = http.MaxBytesReader(nil, r.Body, csrfFormMaxBytes)
	if err := r.ParseForm(); err != nil {
		return ""
	}
	return r.PostForm.Get(interaction.CSRFTokenField)
}

// noCredentialChainRan reports whether the completing chain established
// no authentication of its own, so whatever the response reports has to
// come from an authentication that already existed when the request
// arrived. [interactionExit] routes on it, so the exit kind and the
// record the response reads cannot disagree about what the chain did.
func noCredentialChainRan(st authn.State) bool {
	return len(st.Factors) == 0
}

// chooserReentryBound narrows [noCredentialChainRan] to the account
// chooser: the user picked a specific existing session, which is named
// on the chain state and is not necessarily the session the request
// arrived with.
func chooserReentryBound(st authn.State) bool {
	return noCredentialChainRan(st) && st.ChooserBoundSubject &&
		st.ChooserGroupID != "" && st.ChooserSelectedSessionID != ""
}

// chooserJustBound reports that the tick from before to after is the one
// in which the account chooser bound a session to stand in for the
// factor chain.
func chooserJustBound(before, after authn.State) bool {
	return !before.ChooserBoundSubject && !after.ReauthRequired && chooserReentryBound(after)
}

// reauthenticateChooserPick holds the session the account chooser just
// bound to the constraints the door applied to the entry session. A
// picked session that may not serve the request sends the chain through
// the factors for its subject instead of letting the terminal gate
// refuse the request. A session that cannot be read is left to the
// terminal gate, which classifies it.
func reauthenticateChooserPick(
	r *http.Request,
	deps resolved,
	state authorize.RequestState,
	st authn.State,
	step interaction.Step,
	now time.Time,
) (authn.State, interaction.Step, error) {
	picked := chooserSessionAuthn{
		deps:      deps,
		groupID:   st.ChooserGroupID,
		sessionID: st.ChooserSelectedSessionID,
		subject:   st.Subject,
	}
	authCtx, err := picked.authContext(r.Context())
	if err != nil {
		return st, step, nil //nolint:nilerr // the terminal exit reads the same session and maps the failure
	}
	if sessionMayServe(r.Context(), deps, state.Library.ToRequest(), authCtx.entry(picked.subject), now) == nil {
		return st, step, nil
	}
	return deps.Authn.Tick(r.Context(), authn.RequireReauth(st), authn.Input{Now: now})
}

// errInteractionNoCAS reports an interaction store that cannot serve the
// compare-and-swap the interaction state machine depends on.
var errInteractionNoCAS = errors.New("interaction store lacks compare-and-swap")

// interactionCAS returns the compare-and-swap view of the interaction store.
func interactionCAS(deps resolved) (store.InteractionStoreCAS, error) {
	cas, ok := deps.Interactions.(store.InteractionStoreCAS)
	if !ok {
		return nil, errInteractionNoCAS
	}
	return cas, nil
}

// setCSRFCookie writes the __Host-oidc_csrf cookie carrying token.
func setCSRFCookie(w http.ResponseWriter, token string) error {
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
