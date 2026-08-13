package authorizeendpoint

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/i18n"
	"github.com/libraz/go-oidc-provider/internal/sessions"
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
	if state.Completion != nil {
		resumeInteractionCompletion(w, r, deps, rec, state)
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
	if err := csrf.CheckOrigin(r, deps.InteractionOrigins); err != nil {
		renderJSONError(w, http.StatusForbidden, errInvalidRequest, "origin not allowed")
		return
	}
	rec, state, ok := loadInteraction(w, r, deps, uid)
	if !ok {
		return
	}
	if !verifyCSRFToken(w, r, deps, uid, rec.Step) {
		return
	}
	if state.Completion != nil {
		resumeInteractionCompletion(w, r, deps, rec, state)
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
//
//nolint:gocognit // The validation and conflict branches preserve the protocol's response distinctions.
func serveInteractionDelete(w http.ResponseWriter, r *http.Request, deps resolved, uid string) {
	if err := csrf.CheckOrigin(r, deps.InteractionOrigins); err != nil {
		renderJSONError(w, http.StatusForbidden, errInvalidRequest, "origin not allowed")
		return
	}
	rec, state, ok := loadInteraction(w, r, deps, uid)
	if !ok {
		return
	}
	if !verifyCSRFToken(w, r, deps, uid, rec.Step) {
		return
	}
	if state.Completion != nil {
		resumeInteractionCompletion(w, r, deps, rec, state)
		return
	}
	cas, ok := deps.Interactions.(store.InteractionStoreCAS)
	if !ok {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "interaction store lacks compare-and-swap")
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
			renderJSONError(w, http.StatusConflict, errInvalidRequest, "interaction changed; reload before cancelling")
			return
		}
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		renderJSONError(w, http.StatusInternalServerError, errServerError, "could not cancel interaction")
		return
	}
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
		failTick(w, r, deps, rec, state, next, now, err)
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
		if errors.Is(err, store.ErrConflict) {
			if savedState.Completion != nil {
				resumeInteractionCompletion(w, r, deps, savedRec, savedState)
				return
			}
			renderJSONError(w, http.StatusConflict, errInvalidRequest, "interaction changed; reload before continuing")
			return
		}
		if errors.Is(err, store.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		renderJSONError(w, http.StatusInternalServerError, errServerError, "could not persist interaction")
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
		renderJSONError(w, http.StatusInternalServerError, errServerError, "could not issue csrf token")
		return
	}
	if err := setCSRFCookie(w, token, deps.InteractionTTL); err != nil {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "could not set csrf cookie")
		return
	}
	stampNoStore(w)
	prompt := *step.Prompt
	// Stamp the CSRF token onto the prompt envelope so a server-
	// rendered Driver can embed it as a hidden form field. SPA
	// drivers that prefer the X-CSRF-Token header may ignore the
	// field; the POST handler accepts both routes, so the choice is
	// the driver's.
	prompt.CSRFToken = token
	if err := stampChooserAddAccountURL(deps, &prompt, next, state); err != nil {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "could not build chooser add-account URL")
		return
	}
	stampPromptLocale(r, deps, &prompt, next, state)
	if err := deps.Driver.Render(w, r, prompt); err != nil {
		// Render's own headers may already be partially written;
		// surfacing a JSON error after that is unsafe so we just
		// bail. The persistent state is consistent.
		return
	}
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
		renderJSONError(w, http.StatusInternalServerError, errServerError, "interaction state corrupted")
		return false
	}
	if bytes.Equal(encoded, state.Authn) {
		return true
	}
	savedRec, savedState, err := persistAuthnState(r.Context(), deps, rec, state, next, rec.Step, now)
	if err == nil {
		return true
	}
	switch {
	case errors.Is(err, store.ErrConflict):
		if savedState.Completion != nil {
			resumeInteractionCompletion(w, r, deps, savedRec, savedState)
			return false
		}
		renderJSONError(w, http.StatusConflict, errInvalidRequest, "interaction changed; reload before continuing")
	case errors.Is(err, store.ErrNotFound):
		http.NotFound(w, r)
	default:
		renderJSONError(w, http.StatusInternalServerError, errServerError, "could not persist interaction")
	}
	return false
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
	case errors.Is(err, authn.ErrFactorAbort):
		// A terminal, user-input-driven factor failure (expired or
		// already-consumed one-time code, active lockout, required
		// reset). Render as a 4xx so the SPA / driver can distinguish it
		// from a real server fault instead of surfacing a 500.
		renderJSONError(w, http.StatusBadRequest, errInvalidRequest, "authentication factor cannot continue")
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
	cas, ok := deps.Interactions.(store.InteractionStoreCAS)
	if !ok {
		return nil, authorize.RequestState{}, errors.New(
			"authorizeendpoint: interaction store lacks compare-and-swap",
		)
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
		renderJSONError(w, http.StatusForbidden, errInvalidRequest, "csrf cookie missing")
		return false
	}
	submitted := r.Header.Get("X-CSRF-Token")
	if submitted == "" {
		submitted = csrfFromForm(r)
	}
	if submitted == "" {
		renderJSONError(w, http.StatusForbidden, errInvalidRequest, "csrf token missing")
		return false
	}
	if !csrf.ConstantTimeEqual(cookieVal.Value, submitted) {
		renderJSONError(w, http.StatusForbidden, errInvalidRequest, "csrf token mismatch")
		return false
	}
	if err := deps.CSRF.VerifyScoped(submitted, uid, scope, deps.now(), deps.InteractionTTL); err != nil {
		renderJSONError(w, http.StatusForbidden, errInvalidRequest, "csrf token rejected")
		return false
	}
	return true
}

// csrfFromForm reads the "csrf_token" field from a url-encoded body.
// It returns "" when the body is not form-encoded so the caller falls
// through to the missing-token branch and JSON-mode SPAs keep their
// header-only contract.
//
// The function caps the body through [http.MaxBytesReader] before
// calling [http.Request.ParseForm] so a hostile client cannot stream
// an unbounded body. A subsequent call to [http.Request.ParseForm]
// from the driver is a no-op (the standard library caches the parsed
// form on the request) so this read does not interfere with the
// driver's own ParseSubmission.
func csrfFromForm(r *http.Request) string {
	ct := r.Header.Get("Content-Type")
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	if strings.TrimSpace(ct) != "application/x-www-form-urlencoded" {
		return ""
	}
	r.Body = http.MaxBytesReader(nil, r.Body, csrfFormMaxBytes)
	if err := r.ParseForm(); err != nil {
		return ""
	}
	return r.PostForm.Get("csrf_token")
}

// resolveGrantACRAMR determines the acr/amr the grant and id_token
// carry, plus the auth time to stamp on the result. On an account
// chooser (select_account) re-entry the user picked an existing session
// instead of running an authenticator, so authnState.Factors is empty
// and [authn.Aggregate] yields acr=""/amr=nil; in that case the auth
// context is seeded from the chosen session and the ACR resolver is
// bypassed, mirroring applyFirstPartySkip on the auto-grant path (both
// copy the session's assurance verbatim rather than re-deriving it from
// an AAL0 factor set) so the grant does not silently downgrade to
// no-acr / no-amr. Otherwise the configured ACR resolver runs.
//
// Copying the picked session's assurance verbatim is only sound when
// that session may serve the request. The entry-time hint matrix
// evaluated max_age / acr_values against the *cookie* session, which is
// not the session the chooser bound, so the constraints are re-checked
// here against the session that actually ends up on the response. A
// stale or too-weak pick terminates the request (errStaleAuthentication
// / errACRUnmet) instead of minting a code.
func resolveGrantACRAMR(
	r *http.Request,
	deps resolved,
	rec *store.Interaction,
	req *authorize.Request,
	authnState authn.State,
	subject string,
	authTime time.Time,
) (string, []string, time.Time, error) {
	acr, amr, level := authn.Aggregate(authnState.Factors)
	chooserReentry := len(authnState.Factors) == 0 && authnState.ChooserBoundSubject &&
		authnState.ChooserGroupID != "" && authnState.ChooserSelectedSessionID != ""
	switch {
	case chooserReentry:
		authCtx, err := deps.Sessions.AuthContext(
			r.Context(),
			authnState.ChooserGroupID,
			authnState.ChooserSelectedSessionID,
		)
		if err != nil {
			return "", nil, time.Time{}, fmt.Errorf(
				"authorizeendpoint: resolve chooser authentication context: %w", err,
			)
		}
		if authCtx.Subject != subject {
			return "", nil, time.Time{}, errors.New(
				"authorizeendpoint: chooser authentication context subject mismatch",
			)
		}
		if err := checkPickedSessionFreshness(req, authCtx, deps.now().UTC()); err != nil {
			return "", nil, time.Time{}, err
		}
		acr = authCtx.ACR
		amr = authCtx.AMR
		if !authCtx.AuthTime.IsZero() {
			authTime = authCtx.AuthTime
		}
	case deps.ACRResolver != nil:
		out := deps.ACRResolver(r.Context(), ACRResolveInput{
			RequestedACRValues: requestedACRValues(req),
			CompletedKinds:     append([]string(nil), authnState.CompletedStepKinds...),
			InternalAAL:        level,
			Subject:            subject,
			ClientID:           rec.ClientID,
			RequestedScopes:    append([]string(nil), req.Scope...),
			RemoteIP:           acrRemoteIP(r, deps, authnState),
			UserAgent:          acrUserAgent(r, authnState),
			AcceptLanguage:     r.Header.Get("Accept-Language"),
		})
		switch {
		case out.OK:
			acr = out.ACR
			if out.AMR != nil {
				amr = append([]string(nil), out.AMR...)
			}
		case essentialACRRequested(req):
			return "", nil, time.Time{}, errACRUnmet
		default:
			acr = ""
		}
	}
	return acr, amr, authTime, nil
}

// errACRUnmet signals that the ceremony reached a context the
// configured ACR policy refused for an acr the request marked
// essential. The caller translates it into the
// unmet_authentication_requirements wire error; flattening the acr to
// "" instead (the treatment a voluntary request gets) would hand the
// relying party a code for an authentication it declared insufficient.
var errACRUnmet = errors.New("authorizeendpoint: essential acr is not satisfied")

// errStaleAuthentication signals that the authentication bound to the
// response is older than the request's max_age, or that the request
// asked for a fresh one with prompt=login. The caller translates it
// into login_required, which is the same error the dispatcher emits
// when the entry session fails the identical check — an RP that uses
// max_age as a step-up gate sees one outcome regardless of which
// account the user picked.
var errStaleAuthentication = errors.New("authorizeendpoint: authentication is older than max_age")

// checkPickedSessionFreshness re-applies the request's freshness and
// authentication-context constraints to the session an account chooser
// bound. The entry-time hint matrix ran the same predicates against the
// cookie session; because the chooser can bind a *different* session,
// the constraints have to hold for the session that actually backs the
// response, on every exit path that emits a code.
//
// The predicates are the dispatcher's, reused verbatim
// (acrUnsatisfiedByRequest, and the max_age arithmetic of
// buildHintState) so the two gates cannot drift apart.
func checkPickedSessionFreshness(
	req *authorize.Request,
	authCtx sessions.SessionAuthContext,
	now time.Time,
) error {
	if req == nil {
		return nil
	}
	if containsString(req.Prompt, interaction.PromptLogin) {
		return errStaleAuthentication
	}
	if req.MaxAge != nil {
		if *req.MaxAge == 0 ||
			now.Sub(authCtx.AuthTime.UTC()) > time.Duration(*req.MaxAge)*time.Second {
			return errStaleAuthentication
		}
	}
	if acrUnsatisfiedByRequest(authCtx.ACR, req) {
		return errACRUnmet
	}
	return nil
}

// acrRemoteIP returns the client IP the ACR policy sees. The chain
// state carries the address /authorize resolved through the
// trusted-proxy chain when it created the interaction, which is the
// address the ceremony actually started from; it is preferred over
// re-resolving the terminal request so a policy sees one address for
// the whole login. The fallback re-resolves the current request
// through the same trusted-proxy path for chains that predate the
// recorded field. An unresolvable address yields "" rather than
// netip.Addr's "invalid IP" placeholder so the policy's no-hints
// branch stays reachable.
func acrRemoteIP(r *http.Request, deps resolved, st authn.State) string {
	if st.RemoteIP.IsValid() {
		return st.RemoteIP.String()
	}
	if ip := clientIPFromRequest(r, deps); ip.IsValid() {
		return ip.String()
	}
	return ""
}

// acrUserAgent mirrors [acrRemoteIP] for the User-Agent hint: the
// value recorded on the chain wins, and the terminal request's header
// (truncated to the same bound the chain applies) is the fallback.
func acrUserAgent(r *http.Request, st authn.State) string {
	if st.UserAgent != "" {
		return st.UserAgent
	}
	return truncateUserAgent(r.UserAgent())
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
		if !claimTerminalInteraction(w, r, deps, rec) {
			return
		}
		clearCookie(w, cookie.InteractionProfile)
		clearCookie(w, cookie.CSRFProfile)
		emitAuthorizeError(w, r, deps, req, errAccessDenied, "subject was not authenticated")
		return
	}
	acr, amr, authTime, err := resolveGrantACRAMR(
		r,
		deps,
		rec,
		req,
		authnState,
		result.Subject,
		result.AuthTime,
	)
	if err != nil {
		switch {
		case errors.Is(err, errACRUnmet):
			failUnmetAuthenticationRequirements(w, r, deps, rec, req)
		case errors.Is(err, errStaleAuthentication):
			failTerminalInteraction(w, r, deps, rec, req, errLoginRequired,
				"the selected account's authentication is older than max_age")
		default:
			emitAuthorizeError(w, r, deps, req, errServerError, "could not resolve authentication context")
		}
		return
	}
	result.AuthTime = authTime
	decision := resolveScopeDecision(authnState, result, req.Scope)
	intent, err := prepareCompletionIntent(
		r,
		deps,
		rec,
		authnState,
		result,
		acr,
		amr,
		decision,
		req.Scope,
	)
	if err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not prepare authorization completion")
		return
	}
	rec, state, err = persistCompletionIntent(r.Context(), deps, rec, state, intent)
	if err != nil {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "could not persist authorization completion")
		return
	}
	resumeInteractionCompletion(w, r, deps, rec, state)
}

// failUnmetAuthenticationRequirements ends the interaction when the
// completed ceremony cannot satisfy an acr the request marked
// essential. The interaction is claimed and its cookies cleared before
// the error is emitted, mirroring the "subject was not authenticated"
// branch: the ceremony is over either way, and leaving the record
// behind would let the same completed chain be replayed for a code.
func failUnmetAuthenticationRequirements(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	rec *store.Interaction,
	req *authorize.Request,
) {
	failTerminalInteraction(w, r, deps, rec, req, errUnmetAuthenticationRequirements,
		"the authentication performed does not satisfy the requested acr")
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
	clearCookie(w, cookie.InteractionProfile)
	clearCookie(w, cookie.CSRFProfile)
	emitAuthorizeError(w, r, deps, req, code, description)
}

func claimTerminalInteraction(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	rec *store.Interaction,
) bool {
	cas, ok := deps.Interactions.(store.InteractionStoreCAS)
	if !ok {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "interaction store lacks compare-and-swap")
		return false
	}
	if err := cas.DeleteIfUnchanged(r.Context(), rec); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			renderJSONError(w, http.StatusGone, errInvalidRequest, "interaction already complete")
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
			renderJSONError(w, http.StatusConflict, errInvalidRequest, "interaction changed; reload before continuing")
			return false
		}
		renderJSONError(w, http.StatusInternalServerError, errServerError, "could not claim interaction")
		return false
	}
	return true
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

// setSessionCookieWithMaxAge writes the encrypted browser-session cookie. A
// non-zero expiresAt is used to cap the browser idle lifetime at the same
// absolute expiry the session manager enforced server-side.
func setSessionCookieWithMaxAge(w http.ResponseWriter, value string, expiresAt, now time.Time) error {
	profile := cookie.SessionProfile
	if !expiresAt.IsZero() {
		remaining := expiresAt.UTC().Sub(now.UTC())
		if remaining <= 0 {
			return sessions.ErrCurrentSessionExpired
		}
		if remaining < profile.MaxAge {
			// Cookie Max-Age is expressed in whole seconds. Preserve a
			// positive sub-second server-side lifetime as one second rather
			// than truncating it to zero, which would silently turn the
			// authenticated cookie into a browser-session cookie.
			seconds := remaining / time.Second
			if remaining%time.Second != 0 {
				seconds++
			}
			profile.MaxAge = seconds * time.Second
		}
	}
	c, err := cookie.Build(profile, value)
	if err != nil {
		return fmt.Errorf("authorizeendpoint: build session cookie: %w", err)
	}
	http.SetCookie(w, c)
	return nil
}

// scopeDecision is what the ceremony decided about scope. The
// distinction the type exists to carry is "the user answered" versus
// "no ceremony ran": an approval of nothing and an absent ceremony
// both leave the approved set empty, and only the latter may fall back
// to the full requested set.
type scopeDecision struct {
	// answered reports that a consent-shaped Interaction returned a
	// scope decision during this attempt.
	answered bool

	// presented is the scope set the ceremony put in front of the
	// user. The ceremony is authoritative over exactly these names:
	// scopes outside the set were never up for review and must not be
	// touched.
	presented []string

	// approved is the subset the user accepted.
	approved []string
}

// resolveScopeDecision reads the ceremony's verdict off the terminal
// Result and the orchestrator state.
func resolveScopeDecision(authnState authn.State, result interaction.Result, requested []string) scopeDecision {
	if !authnState.ScopeApprovalRecorded {
		return scopeDecision{}
	}
	presented := authnState.RequestedScopes
	if len(presented) == 0 {
		presented = requested
	}
	return scopeDecision{
		answered:  true,
		presented: append([]string(nil), presented...),
		approved:  append([]string(nil), result.Scope...),
	}
}

// grantScope picks the scope slice the authorize-code mint records into
// the grant and the authorization code. An answered ceremony wins
// outright — including when it approved nothing. The fallback to the
// requested set applies only to chains that ran no consent screen
// (existing grant covered, or the embedder suppressed consent).
func (d scopeDecision) grantScope(requested []string) []string {
	if d.answered {
		return append([]string(nil), d.approved...)
	}
	return append([]string(nil), requested...)
}

// declined is the set the ceremony presented and the user did not
// approve. It is what a grant amendment removes.
func (d scopeDecision) declined() []string {
	if !d.answered {
		return nil
	}
	out := make([]string, 0, len(d.presented))
	for _, s := range d.presented {
		if !containsString(d.approved, s) {
			out = append(out, s)
		}
	}
	return out
}

// grantUpsert collects the inputs upsertGrant needs. The struct exists
// so the helper stays under the linter's parameter limit and so future
// fields (e.g., per-claim consent payload) can be added without
// churning the call site.
type grantUpsert struct {
	Subject  string
	ClientID string
	Scope    []string
	AuthTime time.Time
	ACR      string
	AMR      []string

	// DeclinedScope is the set a consent ceremony presented and the
	// user refused. The ordinary upsert removes these names from the
	// reused grant, which is the only thing that makes a withdrawal
	// observable: leaving them on the record means the next request
	// for the same scope is reported as already consented and is
	// served without a ceremony. Empty for every non-consent-driven
	// call (silent re-stamp, first-party auto-grant), which keeps
	// those paths widen-only as before.
	DeclinedScope []string

	// Claims is the parsed OIDC Core 1.0 §5.5 "claims" request
	// parameter as carried by the authorize / PAR request. The
	// upsertGrant helper persists it onto the grant record so the
	// userinfo and id_token issuance paths can honour the requested
	// claim projection. A nil pointer leaves the grant's existing
	// Claims map untouched.
	Claims *authorize.ClaimsRequest

	// AuthorizationDetails is the validated RFC 9396 authorization_details
	// the request carried. upsertGrant persists it verbatim so the token
	// endpoint and introspection can echo it. Nil leaves the grant's
	// existing details untouched on the refresh path.
	AuthorizationDetails []map[string]any

	// GMAction is the Grant Management draft action ("create" / "replace"
	// / "merge") or empty for the ordinary (non-GM) upsert. GMGrantID is
	// the targeted grant for replace / merge.
	GMAction   string
	GMGrantID  string
	NewGrantID string

	Now time.Time
}

// errGrantNotOwned signals a Grant Management replace / merge referenced a
// grant_id that does not resolve to a grant owned by the authenticated
// (subject, client). The caller maps it to the OAuth invalid_grant wire
// error. Keeping it distinct from a store fault prevents a cross-subject
// or cross-client grant from being mutated.
var errGrantNotOwned = errors.New("authorizeendpoint: grant_id not owned by subject/client")

// upsertGrant ensures a grant exists for (subject, clientID) covering
// at least the supplied scope. The auth context (AuthTime, ACR, AMR) is
// refreshed on every call so the persisted record always reflects the
// most recent interactive authentication; OIDC Core 1.0 §12 requires
// refresh-token-derived id_tokens to carry the same acr/amr as the
// originating authentication, and the library reads them back through
// the grant on every token issuance.
func upsertGrant(
	ctx context.Context,
	deps resolved,
	in grantUpsert,
) (*store.Grant, error) {
	switch in.GMAction {
	case gmActionReplace, gmActionMerge:
		return mutateManagedGrant(ctx, deps, in)
	case gmActionCreate:
		return createGrant(ctx, deps, in)
	default:
		return reuseOrCreateGrant(ctx, deps, in)
	}
}

// reuseOrCreateGrant is the ordinary (non-Grant-Management) path: it
// amends the existing (subject, client) grant, and mints one only when
// the subject has none for this client.
//
// Amending covers the widening case as well as the covered one. A
// repeat authorization asking for more than the record holds used to
// mint a second grant carrying the union, which left the superseded
// record — and its live refresh chain — behind with nothing reaping it:
// the consent screen shows one relationship, so a second row is a
// grant the user cannot see and cannot revoke. Grant Management's
// create action still mints per authorization, but it reaches
// [createGrant] through [upsertGrant] rather than through here, so the
// addressable-unit semantics that action promises are unaffected.
//
// When the call comes from an answered consent ceremony
// ([grantUpsert.DeclinedScope] non-empty) the record is first narrowed:
// the ceremony is authoritative over the names it presented, so a scope
// the user unticked leaves the record before the union re-adds what was
// approved.
func reuseOrCreateGrant(ctx context.Context, deps resolved, in grantUpsert) (*store.Grant, error) {
	now := in.Now.UTC()
	encodedClaims := authorize.EncodeClaimsToGrant(in.Claims)
	existing, err := deps.Grants.FindBySubjectClient(ctx, in.Subject, in.ClientID)
	if validationErr := validateReusableGrantLookup(existing, err, in); validationErr != nil {
		return nil, validationErr
	}
	if err != nil || existing == nil {
		return createGrant(ctx, deps, in)
	}
	if len(in.DeclinedScope) > 0 {
		existing.Scope = removeScopes(existing.Scope, in.DeclinedScope)
	}
	existing.Scope = unionScopes(existing.Scope, in.Scope)
	existing.UpdatedAt = now
	existing.AuthTime = in.AuthTime
	existing.ACR = in.ACR
	existing.AMR = append(existing.AMR[:0:0], in.AMR...)
	if encodedClaims != nil {
		existing.Claims = encodedClaims
	}
	if in.AuthorizationDetails != nil {
		existing.AuthorizationDetails = appendAuthorizationDetails(
			existing.AuthorizationDetails,
			in.AuthorizationDetails,
		)
	}
	if err := deps.Grants.Save(ctx, existing); err != nil {
		return nil, fmt.Errorf("authorizeendpoint: refresh grant: %w", err)
	}
	return existing, nil
}

func validateReusableGrantLookup(
	existing *store.Grant,
	err error,
	in grantUpsert,
) error {
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("authorizeendpoint: find reusable grant: %w", err)
	}
	if existing == nil {
		return errors.New("authorizeendpoint: reusable grant lookup returned nil record")
	}
	if existing.ID == "" || existing.Subject != in.Subject || existing.ClientID != in.ClientID {
		return errors.New("authorizeendpoint: reusable grant lookup returned mismatched record")
	}
	return nil
}

// createGrant mints a brand-new grant. Grant Management's create action
// uses it directly (a fresh grant_id every time, never reusing an
// existing record), and the ordinary path falls back to it when no
// reusable grant exists.
func createGrant(ctx context.Context, deps resolved, in grantUpsert) (*store.Grant, error) {
	now := in.Now.UTC()
	grantID := in.NewGrantID
	if grantID == "" {
		var err error
		grantID, err = newRandomB64(uidByteLength)
		if err != nil {
			return nil, err
		}
	}
	g := &store.Grant{
		ID:                   grantID,
		Subject:              in.Subject,
		ClientID:             in.ClientID,
		Scope:                append([]string(nil), in.Scope...),
		AuthTime:             in.AuthTime,
		ACR:                  in.ACR,
		AMR:                  append([]string(nil), in.AMR...),
		Claims:               authorize.EncodeClaimsToGrant(in.Claims),
		AuthorizationDetails: cloneGrantAuthorizationDetails(in.AuthorizationDetails),
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := deps.Grants.Save(ctx, g); err != nil {
		return nil, fmt.Errorf("authorizeendpoint: persist grant: %w", err)
	}
	return g, nil
}

// mutateManagedGrant applies a Grant Management replace / merge to the
// targeted grant_id. It enforces the ownership invariant — the grant MUST
// resolve to one owned by the authenticated (subject, client) — before any
// mutation, returning [errGrantNotOwned] otherwise so a hostile request
// cannot read or rewrite another principal's grant.
func mutateManagedGrant(ctx context.Context, deps resolved, in grantUpsert) (*store.Grant, error) {
	g, err := deps.Grants.Find(ctx, in.GMGrantID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, errGrantNotOwned
		}
		return nil, fmt.Errorf("authorizeendpoint: find managed grant: %w", err)
	}
	if g == nil {
		return nil, errors.New("authorizeendpoint: managed grant lookup returned nil record")
	}
	if g.ID == "" || g.ID != in.GMGrantID {
		return nil, errors.New("authorizeendpoint: managed grant lookup returned mismatched record")
	}
	if g.ClientID != in.ClientID || g.Subject != in.Subject {
		return nil, errGrantNotOwned
	}
	switch in.GMAction {
	case gmActionReplace:
		g.Scope = append([]string(nil), in.Scope...)
		g.AuthorizationDetails = cloneGrantAuthorizationDetails(in.AuthorizationDetails)
	case gmActionMerge:
		g.Scope = unionScopes(g.Scope, in.Scope)
		g.AuthorizationDetails = appendAuthorizationDetails(g.AuthorizationDetails, in.AuthorizationDetails)
	}
	g.AuthTime = in.AuthTime
	g.ACR = in.ACR
	g.AMR = append(g.AMR[:0:0], in.AMR...)
	if encodedClaims := authorize.EncodeClaimsToGrant(in.Claims); encodedClaims != nil {
		g.Claims = encodedClaims
	}
	g.UpdatedAt = in.Now.UTC()
	if err := deps.Grants.Save(ctx, g); err != nil {
		return nil, fmt.Errorf("authorizeendpoint: replace/merge grant: %w", err)
	}
	return g, nil
}

// unionScopes returns base with every entry of add that is not already
// present, preserving order (base first, then new entries).
// removeScopes returns base without any element of drop, preserving
// base's order.
func removeScopes(base, drop []string) []string {
	if len(drop) == 0 {
		return base
	}
	out := make([]string, 0, len(base))
	for _, s := range base {
		if !containsString(drop, s) {
			out = append(out, s)
		}
	}
	return out
}

func unionScopes(base, add []string) []string {
	seen := make(map[string]struct{}, len(base))
	out := append([]string(nil), base...)
	for _, s := range base {
		seen[s] = struct{}{}
	}
	for _, s := range add {
		if _, ok := seen[s]; !ok {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

// appendAuthorizationDetails merges the existing and new
// authorization_details for a Grant Management merge. Elements are
// deep-cloned so the persisted grant does not alias the request's maps, and
// an added element that is deep-equal to one already present is skipped so a
// repeated merge of the same authorization_details does not accumulate
// unbounded duplicates on the grant.
func appendAuthorizationDetails(base, add []map[string]any) []map[string]any {
	out := cloneGrantAuthorizationDetails(base)
	for _, el := range cloneGrantAuthorizationDetails(add) {
		dup := false
		for _, have := range out {
			if reflect.DeepEqual(have, el) {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, el)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// cloneGrantAuthorizationDetails deep-copies the authorization_details
// slice so the persisted grant does not alias the request's maps. A nil or
// empty slice yields nil.
func cloneGrantAuthorizationDetails(in []map[string]any) []map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make([]map[string]any, len(in))
	for i, el := range in {
		if el == nil {
			continue
		}
		cp := make(map[string]any, len(el))
		for k, v := range el {
			cp[k] = v
		}
		out[i] = cp
	}
	return out
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

// stampChooserAddAccountURL fills the chooser prompt's "add another
// account" target from the persisted authorize request. The URL carries
// OP-private markers; /authorize honours them only when the browser still
// presents a session cookie for the same chooser group.
//
// The target is a bare query-parameter /authorize URL. When the deployment
// mandates PAR (RequirePAR, e.g. FAPI 2.0) /authorize rejects any request that
// lacks a request_uri before the markers are read, so such a URL is
// unfollowable. Rather than hand the chooser UI a link the OP itself will
// reject, the AddAccountURL is left empty under RequirePAR; a driver renders
// the "add account" affordance only when the field is non-empty. PAR-minted
// add-account re-entry is a separate feature, not wired in this path.
func stampChooserAddAccountURL(deps resolved, prompt *interaction.Prompt, st authn.State, reqState authorize.RequestState) error {
	if prompt == nil || prompt.Type != authn.ChooserPromptType || st.ChooserGroupID == "" {
		return nil
	}
	if deps.RequirePAR {
		return nil
	}
	data, ok := prompt.Data.(interaction.ChooserPromptData)
	if !ok {
		return nil
	}
	values, err := chooserAddAccountValues(reqState.Library, st.ChooserGroupID)
	if err != nil {
		return err
	}
	data.AddAccountURL = deps.AuthorizePath + "?" + values.Encode()
	prompt.Data = data
	return nil
}

func chooserAddAccountValues(s authorize.RequestSnapshot, chooserGroupID string) (url.Values, error) {
	values := url.Values{}
	setIfNotEmpty(values, "client_id", s.ClientID)
	setIfNotEmpty(values, "response_type", s.ResponseType)
	setIfNotEmpty(values, "redirect_uri", s.RedirectURI)
	setIfNotEmpty(values, "state", s.State)
	setIfNotEmpty(values, "nonce", s.Nonce)
	setIfNotEmpty(values, "code_challenge", s.CodeChallenge)
	setIfNotEmpty(values, "code_challenge_method", s.CodeChallengeMethod)
	setIfNotEmpty(values, "scope", strings.Join(s.Scope, " "))
	setIfNotEmpty(values, "resource", s.Resource)
	setIfNotEmpty(values, "acr_values", strings.Join(s.ACRValues, " "))
	setIfNotEmpty(values, "ui_locales", strings.Join(s.UILocales, " "))
	if s.MaxAge != nil {
		values.Set("max_age", strconv.FormatInt(int64(*s.MaxAge), 10))
	}
	setIfNotEmpty(values, "login_hint", s.LoginHint)
	setIfNotEmpty(values, "response_mode", s.ResponseMode)
	setIfNotEmpty(values, "dpop_jkt", s.DPoPJKT)
	if s.Claims != nil {
		raw, err := json.Marshal(s.Claims)
		if err != nil {
			return nil, fmt.Errorf("authorizeendpoint: marshal claims for chooser add-account: %w", err)
		}
		values.Set("claims", string(raw))
	}
	if len(s.AuthorizationDetails) > 0 {
		raw, err := json.Marshal(s.AuthorizationDetails)
		if err != nil {
			return nil, fmt.Errorf("authorizeendpoint: marshal authorization_details for chooser add-account: %w", err)
		}
		values.Set("authorization_details", string(raw))
	}
	setIfNotEmpty(values, "grant_management_action", s.GrantManagementAction)
	setIfNotEmpty(values, "grant_id", s.GrantID)
	values.Set("prompt", interaction.PromptLogin)
	values.Set("_oidc_add_account", "1")
	values.Set("_oidc_chooser_group", chooserGroupID)
	return values, nil
}

func setIfNotEmpty(values url.Values, name, value string) {
	if value != "" {
		values.Set(name, value)
	}
}

// stampPromptLocale walks the locale priority chain through the
// configured [i18n.Resolver] and stamps the result onto prompt.
// A nil resolver leaves the locale fields empty so direct callers
// (unit tests, embedders that do not need i18n) keep the legacy
// shape. The cookie is read from the request unparsed; the resolver
// performs the BCP 47 normalisation.
func stampPromptLocale(r *http.Request, deps resolved, prompt *interaction.Prompt, st authn.State, reqState authorize.RequestState) {
	if deps.LocaleResolver == nil || prompt == nil {
		return
	}
	cookieVal := ""
	if c, err := r.Cookie(cookie.LocaleProfile.Name); err == nil {
		cookieVal = c.Value
	}
	tag := deps.LocaleResolver.Resolve(r.Context(), i18n.Request{
		Subject:        st.Subject,
		UILocales:      reqState.Library.UILocales,
		Cookie:         cookieVal,
		AcceptLanguage: r.Header.Get("Accept-Language"),
	})
	prompt.Locale = string(tag)
	if len(reqState.Library.UILocales) > 0 {
		prompt.UILocalesHint = slices.Clone(reqState.Library.UILocales)
	}
	available := deps.LocaleResolver.Available()
	if len(available) > 0 {
		out := make([]string, len(available))
		for i, t := range available {
			out[i] = string(t)
		}
		prompt.LocalesAvailable = out
	}
}
