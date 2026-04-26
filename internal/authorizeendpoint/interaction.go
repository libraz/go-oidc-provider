package authorizeendpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// maxInteractionBodyBytes caps the JSON body size for /interaction POSTs.
// The body carries [interaction.Result] only; a few KiB is far above any
// legitimate payload while bounding memory use against pathological inputs
// (gosec G120).
const maxInteractionBodyBytes = 32 * 1024

// stepResponse is the JSON shape the /interaction GET handler returns.
// Field names are snake_case to match the convention in
// [internal/tokenendpoint] and on the SPA contract documented in §A.9.
type stepResponse struct {
	Hint      hintBody `json:"hint"`
	CSRF      string   `json:"csrf"`
	ExpiresAt int64    `json:"expires_at"`
}

// hintBody is the JSON shape of [interaction.Hint] over the wire. It is a
// distinct type so adding fields does not force callers to recompile.
type hintBody struct {
	Prompt  string   `json:"prompt"`
	Reasons []string `json:"reasons,omitempty"`
}

// resultBody is the JSON shape of [interaction.Result] inbound from the
// SPA. The wire form uses snake_case field names; AuthTime is RFC 3339 so
// the SPA can emit an ISO 8601 timestamp directly.
type resultBody struct {
	SubjectHint   string   `json:"subject_hint"`
	GrantedScopes []string `json:"granted_scopes,omitempty"`
	AccountID     string   `json:"account_id,omitempty"`
	Aborted       bool     `json:"aborted,omitempty"`
	AuthTime      string   `json:"auth_time,omitempty"`
	AMR           []string `json:"amr,omitempty"`
	ACR           string   `json:"acr,omitempty"`
}

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

// serveInteractionGet returns the next [Step] the SPA should render. The
// handler decodes the persisted state, asks the Driver to refine it, and
// mints a fresh CSRF token bound to the UID.
func serveInteractionGet(w http.ResponseWriter, r *http.Request, deps resolved, uid string) {
	rec, _, ok := loadInteraction(w, r, deps, uid)
	if !ok {
		return
	}
	active, _ := resolveSession(r, deps)
	step, err := deps.Driver.Offer(r.Context(), interaction.Request{
		UID:            uid,
		ClientID:       rec.ClientID,
		CurrentSubject: currentSubject(active),
	})
	if err != nil {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "interaction driver failed")
		return
	}
	now := deps.now().UTC()
	token, err := deps.CSRF.Issue(uid, now)
	if err != nil {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "could not issue csrf token")
		return
	}
	if err := setCSRFCookie(w, token, deps.InteractionTTL); err != nil {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "could not set csrf cookie")
		return
	}
	prompt := step.Hint.Prompt
	if prompt == "" {
		prompt = rec.Step
	}
	stampNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(stepResponse{
		Hint:      hintBody{Prompt: prompt, Reasons: slices.Clone(step.Hint.Reasons)},
		CSRF:      token,
		ExpiresAt: rec.ExpiresAt.UTC().Unix(),
	})
}

// serveInteractionPost accepts the SPA's [Result] payload, runs it through
// the Driver, and either persists a follow-up Step or terminates the
// interaction (success / abort).
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
	body, ok := decodeResult(w, r)
	if !ok {
		return
	}
	result, ok := buildResult(w, body)
	if !ok {
		return
	}
	dec, err := deps.Driver.Verify(r.Context(), interaction.Request{
		UID:            uid,
		ClientID:       rec.ClientID,
		CurrentSubject: currentSubjectFromCookie(r, deps),
	}, result)
	if err != nil {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "interaction driver failed")
		return
	}
	if dec.Continue {
		persistFollowUp(w, r, deps, rec, state, dec)
		return
	}
	terminateInteraction(w, r, deps, rec, state, result)
}

// serveInteractionDelete cancels the interaction. The Driver is notified
// best-effort; cancellation is idempotent so a stale UID still returns 204.
func serveInteractionDelete(w http.ResponseWriter, r *http.Request, deps resolved, uid string) {
	rec, _, ok := loadInteraction(w, r, deps, uid)
	if !ok {
		return
	}
	_ = deps.Driver.Cancel(r.Context(), interaction.Request{
		UID:            uid,
		ClientID:       rec.ClientID,
		CurrentSubject: currentSubjectFromCookie(r, deps),
	})
	_ = deps.Interactions.Delete(r.Context(), uid)
	clearCookie(w, cookie.InteractionProfile)
	clearCookie(w, cookie.CSRFProfile)
	stampNoStore(w)
	w.WriteHeader(http.StatusNoContent)
}

// loadInteraction fetches the persisted record and decodes its state
// payload. On failure the handler emits the matching response and returns
// ok=false so the caller can stop.
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

// verifyCSRFToken enforces the double-submit pattern. It returns true on
// success; on failure it has already written the response.
func verifyCSRFToken(w http.ResponseWriter, r *http.Request, deps resolved, uid string) bool {
	cookieVal, err := r.Cookie(cookie.CSRFProfile.Name)
	if err != nil || cookieVal == nil || cookieVal.Value == "" {
		renderJSONError(w, http.StatusForbidden, errInvalidRequest, "csrf cookie missing")
		return false
	}
	header := r.Header.Get("X-CSRF-Token")
	if header == "" {
		// Form fallback so SPA frameworks that prefer a hidden input
		// can still drive the endpoint. Bound the body before parsing
		// so a malicious caller cannot exhaust memory.
		r.Body = http.MaxBytesReader(w, r.Body, maxInteractionBodyBytes)
		if err := r.ParseForm(); err == nil {
			header = r.PostForm.Get("csrf_token")
		}
	}
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

// decodeResult reads and parses the JSON body. On failure it has already
// written the response.
func decodeResult(w http.ResponseWriter, r *http.Request) (resultBody, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxInteractionBodyBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var body resultBody
	if err := dec.Decode(&body); err != nil {
		renderJSONError(w, http.StatusBadRequest, errInvalidRequest, "invalid interaction body")
		return resultBody{}, false
	}
	return body, true
}

// buildResult converts the wire body into [interaction.Result]. The only
// transformation is RFC 3339 → time.Time on AuthTime.
func buildResult(w http.ResponseWriter, body resultBody) (interaction.Result, bool) {
	var authTime time.Time
	if body.AuthTime != "" {
		t, err := time.Parse(time.RFC3339, body.AuthTime)
		if err != nil {
			renderJSONError(w, http.StatusBadRequest, errInvalidRequest, "auth_time must be RFC 3339")
			return interaction.Result{}, false
		}
		authTime = t.UTC()
	}
	return interaction.Result{
		SubjectHint:   body.SubjectHint,
		GrantedScopes: slices.Clone(body.GrantedScopes),
		AccountID:     body.AccountID,
		Aborted:       body.Aborted,
		AuthTime:      authTime,
		AMR:           slices.Clone(body.AMR),
		ACR:           body.ACR,
	}, true
}

// persistFollowUp saves the Driver-supplied next step and returns its JSON
// representation so the SPA can render the next prompt.
func persistFollowUp(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	rec *store.Interaction,
	state authorize.RequestState,
	dec interaction.Decision,
) {
	now := deps.now().UTC()
	rec.Step = dec.Next.Hint.Prompt
	rec.UpdatedAt = now
	// Re-marshal because the snapshot may carry a CreatedUnix that is
	// now stale; the library snapshot itself is unchanged so the
	// round-trip is cheap.
	raw, err := authorize.MarshalState(state)
	if err != nil {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "could not marshal interaction state")
		return
	}
	rec.RawState = raw
	if err := deps.Interactions.Save(r.Context(), rec); err != nil {
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
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(stepResponse{
		Hint:      hintBody{Prompt: dec.Next.Hint.Prompt, Reasons: slices.Clone(dec.Next.Hint.Reasons)},
		CSRF:      token,
		ExpiresAt: rec.ExpiresAt.UTC().Unix(),
	})
}

// terminateInteraction is the happy-path / abort branch of the POST
// handler. It deletes the interaction record, clears the cookies, and
// either redirects with code+state (success) or with access_denied (abort).
func terminateInteraction(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	rec *store.Interaction,
	state authorize.RequestState,
	result interaction.Result,
) {
	req := state.Library.ToRequest()
	if result.Aborted {
		_ = deps.Interactions.Delete(r.Context(), rec.ID)
		clearCookie(w, cookie.InteractionProfile)
		clearCookie(w, cookie.CSRFProfile)
		redirectError(w, r, req.RedirectURI, errAccessDenied, "user aborted the interaction", req.State)
		return
	}
	if err := finalizeInteraction(w, r, deps, rec, req, result); err != nil {
		// finalizeInteraction has already written a response on failure.
		return
	}
}

// finalizeInteraction persists the session + grant + code resulting from a
// successful interaction and emits the redirect to the RP. The function
// returns an error when it has already written a response so the caller
// can stop without a second write.
func finalizeInteraction(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	rec *store.Interaction,
	req *authorize.Request,
	result interaction.Result,
) error {
	if result.SubjectHint == "" {
		// The Driver claimed the interaction is terminal but did not
		// provide a subject. Translate to access_denied so the RP sees
		// a determinate outcome.
		_ = deps.Interactions.Delete(r.Context(), rec.ID)
		clearCookie(w, cookie.InteractionProfile)
		clearCookie(w, cookie.CSRFProfile)
		redirectError(w, r, req.RedirectURI, errAccessDenied, "subject was not authenticated", req.State)
		return errors.New("missing subject hint")
	}
	subject := result.SubjectHint
	if err := ensureSession(w, r, deps, result); err != nil {
		_ = deps.Interactions.Delete(r.Context(), rec.ID)
		clearCookie(w, cookie.InteractionProfile)
		clearCookie(w, cookie.CSRFProfile)
		redirectError(w, r, req.RedirectURI, errServerError, "could not establish session", req.State)
		return err
	}
	grant, err := upsertGrant(r.Context(), deps, subject, rec.ClientID, finalScope(result, req), deps.now())
	if err != nil {
		redirectError(w, r, req.RedirectURI, errServerError, "could not record grant", req.State)
		return err
	}
	codeID, err := newRandomB64(codeByteLength)
	if err != nil {
		redirectError(w, r, req.RedirectURI, errServerError, "could not allocate code", req.State)
		return err
	}
	now := deps.now().UTC()
	authCode := &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            rec.ClientID,
		Subject:             subject,
		GrantID:             grant.ID,
		RedirectURI:         req.RedirectURI,
		Scope:               finalScope(result, req),
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
		State:               req.State,
		ExpiresAt:           now.Add(deps.AuthCodeTTL),
		CreatedAt:           now,
	}
	if err := deps.Codes.Save(r.Context(), authCode); err != nil {
		redirectError(w, r, req.RedirectURI, errServerError, "could not persist authorization code", req.State)
		return err
	}
	_ = deps.Interactions.Delete(r.Context(), rec.ID)
	clearCookie(w, cookie.InteractionProfile)
	clearCookie(w, cookie.CSRFProfile)
	stampNoStore(w)
	http.Redirect(w, r, buildSuccessRedirect(req.RedirectURI, codeID, req.State), http.StatusFound)
	return nil
}

// ensureSession either reuses the session referenced by the cookie or
// issues a fresh one when no session exists or the cookie is invalid.
// The freshly-issued cookie is set on the response writer.
func ensureSession(w http.ResponseWriter, r *http.Request, deps resolved, result interaction.Result) error {
	active, err := resolveSession(r, deps)
	if err == nil && active != nil && active.Session != nil && active.Session.Subject == result.SubjectHint {
		// Session already represents this subject; reuse it.
		return nil
	}
	out, err := deps.Sessions.Issue(r.Context(), sessions.Login{
		Subject:  result.SubjectHint,
		AuthTime: result.AuthTime,
		AMR:      slices.Clone(result.AMR),
		ACR:      result.ACR,
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

// upsertGrant ensures a grant exists for (subject, clientID) covering at
// least the supplied scope. Returns the persisted grant.
func upsertGrant(
	ctx context.Context,
	deps resolved,
	subject, clientID string,
	scope []string,
	now time.Time,
) (*store.Grant, error) {
	existing, err := deps.Grants.FindBySubjectClient(ctx, subject, clientID)
	if err == nil && existing != nil && scopeIsSubset(scope, existing.Scope) {
		// Already covered; touch UpdatedAt so auth_time tracking
		// follows the latest interaction.
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

// finalScope intersects the Driver-declared GrantedScopes with the
// snapshotted request scope. An empty GrantedScopes yields the full
// request scope (the driver expressed no narrowing).
func finalScope(result interaction.Result, req *authorize.Request) []string {
	if len(result.GrantedScopes) == 0 {
		return append([]string(nil), req.Scope...)
	}
	out := make([]string, 0, len(result.GrantedScopes))
	for _, s := range result.GrantedScopes {
		if containsString(req.Scope, s) {
			out = append(out, s)
		}
	}
	return out
}

// currentSubjectFromCookie resolves the current subject from the request
// cookie or returns empty when no live session is bound. It silently
// swallows resolve errors because the value is only used for Driver hints.
func currentSubjectFromCookie(r *http.Request, deps resolved) string {
	active, err := resolveSession(r, deps)
	if err != nil || active == nil || active.Session == nil {
		return ""
	}
	return active.Session.Subject
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
