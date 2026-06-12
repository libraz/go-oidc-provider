package authorizeendpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"slices"
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
	rec, state, ok := loadInteraction(w, r, deps, uid)
	if !ok {
		return
	}
	if !verifyCSRFToken(w, r, deps, uid, rec.Step) {
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
	stampPromptLocale(r, deps, &prompt, next, state)
	if err := deps.Driver.Render(w, r, prompt); err != nil {
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
	acr, amr, level := authn.Aggregate(authnState.Factors)
	if deps.ACRResolver != nil {
		out := deps.ACRResolver(r.Context(), ACRResolveInput{
			RequestedACRValues: append([]string(nil), req.ACRValues...),
			CompletedKinds:     append([]string(nil), authnState.CompletedStepKinds...),
			InternalAAL:        level,
			Subject:            result.Subject,
			ClientID:           rec.ClientID,
			RequestedScopes:    append([]string(nil), req.Scope...),
		})
		if !out.OK {
			acr = ""
		} else {
			acr = out.ACR
			if out.AMR != nil {
				amr = append([]string(nil), out.AMR...)
			}
		}
	}
	if err := ensureSession(w, r, deps, ensureSessionArgs{
		Subject:                  result.Subject,
		AuthTime:                 result.AuthTime,
		AMR:                      amr,
		ACR:                      acr,
		ChooserGroupID:           authnState.ChooserGroupID,
		ChooserSelectedSessionID: authnState.ChooserSelectedSessionID,
		// FreshAuthn signals that an authenticator factor ran during
		// this interaction, so ensureSession can rotate the underlying
		// session ID even when the resulting subject equals the
		// cookie's existing subject (session-fixation defence). The
		// flag is true whenever the chain produced at least one
		// [authn.Factor] entry; consent / chooser-only branches that
		// did not run an authenticator leave Factors empty.
		FreshAuthn: len(authnState.Factors) > 0,
	}); err != nil {
		_ = deps.Interactions.Delete(r.Context(), rec.ID)
		clearCookie(w, cookie.InteractionProfile)
		clearCookie(w, cookie.CSRFProfile)
		emitAuthorizeError(w, r, deps, req, errServerError, "could not establish session")
		return
	}
	grantScope := chooseGrantScope(result.Scope, req.Scope)
	grant, err := upsertGrant(r.Context(), deps, grantUpsert{
		Subject:              result.Subject,
		ClientID:             rec.ClientID,
		Scope:                grantScope,
		AuthTime:             result.AuthTime,
		ACR:                  acr,
		AMR:                  amr,
		Claims:               req.Claims,
		AuthorizationDetails: req.AuthorizationDetails,
		GMAction:             req.GrantManagementAction,
		GMGrantID:            req.GrantID,
		Now:                  deps.now(),
	})
	if errors.Is(err, errGrantNotOwned) {
		emitAuthorizeError(w, r, deps, req, errInvalidGrant, "grant_id is not valid for this client")
		return
	}
	if err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not record grant")
		return
	}
	deps.auditEmitter().Emit(r.Context(), audit.Event{
		Name:     opAuditConsentGranted,
		Level:    audit.LevelInfo,
		Message:  "consent grant recorded",
		ActorID:  result.Subject,
		ClientID: rec.ClientID,
		Extras: map[string]any{
			"grant_id": grant.ID,
			"scope":    append([]string(nil), grant.Scope...),
		},
	})
	codeID, err := newRandomB64(codeByteLength)
	if err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not allocate code")
		return
	}
	if err := consumePARIfNeeded(r.Context(), deps, req); err != nil {
		// A parallel code emission already redeemed the request_uri,
		// or the PAR record vanished; either way RFC 9126 §2.2 forbids
		// issuing a second code. Surface the failure on the redirect
		// channel so the client sees access_denied rather than a
		// silent success.
		emitAuthorizeError(w, r, deps, req, errAccessDenied, "request_uri is no longer valid")
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
		Resource:            req.Resource,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
		State:               req.State,
		DPoPJKT:             req.DPoPJKT,
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

// ensureSessionArgs bundles the inputs ensureSession consumes. The
// chooser-side fields are populated only when the orchestrator ran
// the built-in account chooser; otherwise both are empty and
// ensureSession falls back to Issue.
type ensureSessionArgs struct {
	Subject                  string
	AuthTime                 time.Time
	AMR                      []string
	ACR                      string
	ChooserGroupID           string
	ChooserSelectedSessionID string

	// FreshAuthn reports whether an authenticator factor completed
	// during this interaction. ensureSession reads it to decide
	// whether to rotate the session ID when the cookie-bound
	// subject equals the post-authn subject — a step-up or
	// re-authentication flow that, without rotation, would leave
	// the pre-fixation cookie value valid.
	FreshAuthn bool
}

// ensureSession reuses the cookie-bound session when it represents
// the same subject, switches within the existing chooser group when
// the chooser picked a different account, or issues a fresh session
// otherwise. The resulting cookie is set on the response writer.
//
// Session-fixation defence: when the cookie-bound subject equals the
// post-authn subject AND a fresh authn factor ran during this
// interaction (in.FreshAuthn), the function rotates the underlying
// session ID via [sessions.Manager.Rotate] and writes the new cookie
// before returning. A chain that completed without running an
// authenticator (consent-only, chooser-only) leaves the cookie
// untouched so a same-subject silent re-issue keeps the existing SID.
func ensureSession(w http.ResponseWriter, r *http.Request, deps resolved, in ensureSessionArgs) error {
	active, _ := resolveSession(r, deps)
	if active != nil && active.Session != nil && active.Session.Subject == in.Subject {
		if !in.FreshAuthn {
			return nil
		}
		out, err := deps.Sessions.Rotate(r.Context(), active.Session.ID)
		if err != nil {
			return fmt.Errorf("authorizeendpoint: rotate session: %w", err)
		}
		emitSessionCreated(r.Context(), deps, in.Subject, out.SessionID, out.ChooserGroupID, "rotate")
		return setSessionCookie(w, out.Cookie)
	}
	out, err := pickSessionOutcome(r.Context(), deps, in, active)
	if err != nil {
		return err
	}
	return setSessionCookie(w, out.Cookie)
}

// pickSessionOutcome selects between the Manager paths the terminate
// step needs. A chooser-picked switch wins; every other different-
// subject login starts a fresh chooser group. In particular, a
// non-chooser fresh login MUST NOT call AddAccount just because the
// browser presented an existing session cookie: callers of
// sessions.Manager.AddAccount must prove the user explicitly selected
// "add another account" in the chooser UI.
func pickSessionOutcome(ctx context.Context, deps resolved, in ensureSessionArgs, _ *sessions.Active) (sessions.Outcome, error) {
	if in.ChooserGroupID != "" && in.ChooserSelectedSessionID != "" {
		out, err := deps.Sessions.Switch(ctx, in.ChooserGroupID, in.ChooserSelectedSessionID)
		if err != nil {
			return sessions.Outcome{}, fmt.Errorf("authorizeendpoint: switch session: %w", err)
		}
		return out, nil
	}
	login := sessions.Login{
		Subject:  in.Subject,
		AuthTime: in.AuthTime,
		AMR:      slices.Clone(in.AMR),
		ACR:      in.ACR,
	}
	out, err := deps.Sessions.Issue(ctx, login)
	if err != nil {
		return sessions.Outcome{}, fmt.Errorf("authorizeendpoint: issue session: %w", err)
	}
	emitSessionCreated(ctx, deps, in.Subject, out.SessionID, out.ChooserGroupID, "issue")
	return out, nil
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

// setSessionCookie builds and writes the __Host-oidc_session cookie
// from value. Centralised so the three paths in [pickSessionOutcome]
// share one error string and one Set-Cookie call.
func setSessionCookie(w http.ResponseWriter, value string) error {
	c, err := cookie.Build(cookie.SessionProfile, value)
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
	GMAction  string
	GMGrantID string

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
// refreshes the existing (subject, client) grant when it already covers
// the requested scope, otherwise it mints a fresh one.
func reuseOrCreateGrant(ctx context.Context, deps resolved, in grantUpsert) (*store.Grant, error) {
	now := in.Now.UTC()
	encodedClaims := authorize.EncodeClaimsToGrant(in.Claims)
	existing, err := deps.Grants.FindBySubjectClient(ctx, in.Subject, in.ClientID)
	if err == nil && existing != nil && scopeIsSubset(in.Scope, existing.Scope) {
		existing.UpdatedAt = now
		existing.AuthTime = in.AuthTime
		existing.ACR = in.ACR
		existing.AMR = append(existing.AMR[:0:0], in.AMR...)
		if encodedClaims != nil {
			existing.Claims = encodedClaims
		}
		if in.AuthorizationDetails != nil {
			existing.AuthorizationDetails = cloneGrantAuthorizationDetails(in.AuthorizationDetails)
		}
		if err := deps.Grants.Save(ctx, existing); err != nil {
			return nil, fmt.Errorf("authorizeendpoint: refresh grant: %w", err)
		}
		return existing, nil
	}
	return createGrant(ctx, deps, in)
}

// createGrant mints a brand-new grant. Grant Management's create action
// uses it directly (a fresh grant_id every time, never reusing an
// existing record), and the ordinary path falls back to it when no
// reusable grant exists.
func createGrant(ctx context.Context, deps resolved, in grantUpsert) (*store.Grant, error) {
	now := in.Now.UTC()
	grantID, err := newRandomB64(uidByteLength)
	if err != nil {
		return nil, err
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
	if err != nil || g == nil {
		return nil, errGrantNotOwned
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

// stampPromptLocale walks the §L.2 priority chain through the
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
