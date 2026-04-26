package authorizeendpoint

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// maxAuthorizeFormBytes caps POST /authorize request body size. Authorize
// requests are tiny in practice; this ceiling is well above any legitimate
// payload (the largest field, request_object, comfortably fits in a few
// KiB) while bounding memory use against pathological inputs (gosec G120).
const maxAuthorizeFormBytes = 64 * 1024

// serveAuthorize is the request-scoped entry point for /authorize. It runs
// the validator from [internal/authorize], resolves the active session,
// decides whether the request can be served silently or needs an
// interaction, and dispatches to the matching helper.
func serveAuthorize(w http.ResponseWriter, r *http.Request, deps resolved) {
	if !methodAllowed(r.Method) {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		renderJSONError(w, http.StatusMethodNotAllowed, errInvalidRequest, "method not allowed")
		return
	}
	if r.Method == http.MethodPost {
		if !isFormContent(r.Header.Get("Content-Type")) {
			renderJSONError(w, http.StatusBadRequest, errInvalidRequest,
				"content-type must be application/x-www-form-urlencoded")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxAuthorizeFormBytes)
	}
	req, err := authorize.ParseRequest(r)
	if err != nil {
		writeAuthorizeParseError(w, r, err)
		return
	}
	client, err := deps.Clients.GetClient(r.Context(), req.ClientID)
	if err != nil {
		// Treat a missing or unknown client as an unrecoverable
		// invalid_request: redirect_uri is not yet trusted, so the
		// response MUST be a JSON envelope rather than a redirect.
		renderJSONError(w, http.StatusBadRequest, errInvalidRequest, "client_id is not registered")
		return
	}
	if err := req.Validate(client); err != nil {
		writeAuthorizeValidationError(w, r, req, err)
		return
	}
	dispatchAuthorize(w, r, deps, req, client)
}

// methodAllowed reports whether the HTTP method is one of GET / POST. The
// authorize endpoint accepts both per RFC 6749 §3.1.
func methodAllowed(method string) bool {
	return method == http.MethodGet || method == http.MethodPost
}

// isFormContent reports whether ct is application/x-www-form-urlencoded,
// tolerating optional parameters (charset, boundary, etc.). Mirrors the
// helper in [internal/tokenendpoint] so the two endpoints stay aligned.
func isFormContent(ct string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "application/x-www-form-urlencoded")
}

// writeAuthorizeParseError handles errors emitted by [authorize.ParseRequest].
// Every error at this stage is pre-redirect-URI: there is no trusted
// redirect target, so the response MUST be a JSON envelope.
func writeAuthorizeParseError(w http.ResponseWriter, _ *http.Request, err error) {
	var ae *authorize.Error
	if errors.As(err, &ae) {
		renderJSONError(w, http.StatusBadRequest, ae.Code, ae.Description)
		return
	}
	renderJSONError(w, http.StatusBadRequest, errInvalidRequest, "request could not be parsed")
}

// writeAuthorizeValidationError translates a [authorize.Validate] failure
// into either a redirect or a JSON envelope, depending on whether the
// redirect target has been trusted yet.
func writeAuthorizeValidationError(w http.ResponseWriter, r *http.Request, req *authorize.Request, err error) {
	var ae *authorize.Error
	if !errors.As(err, &ae) {
		renderJSONError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	if !authorize.IsRedirectSafe(err) {
		renderJSONError(w, http.StatusBadRequest, ae.Code, ae.Description)
		return
	}
	redirectError(w, r, req.RedirectURI, ae.Code, ae.Description, req.State)
}

// authorizeDecision captures the four outcomes the dispatcher chooses
// between. Centralising the decision keeps the cyclomatic complexity of
// [dispatchAuthorize] under the project lint cap.
type authorizeDecision int

const (
	decisionInteract authorizeDecision = iota
	decisionMint
	decisionLoginRequired
	decisionConsentRequired
	decisionInteractionRequired
)

// dispatchAuthorize chooses between the three terminal outcomes (silent
// mint, redirect-with-error for prompt=none failures, or start an
// interaction) based on the session state and the request flags.
func dispatchAuthorize(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	req *authorize.Request,
	client *store.Client,
) {
	now := deps.now()
	active, sessErr := resolveSession(r, deps)
	if sessErr != nil && !errors.Is(sessErr, sessions.ErrCookieInvalid) && !errors.Is(sessErr, sessions.ErrCurrentSessionExpired) {
		// Underlying store fault — surface a server_error redirect so the
		// RP knows the failure was on the OP's side. The redirect_uri is
		// already trusted at this point (Validate returned nil), hence
		// safe to redirect.
		redirectError(w, r, req.RedirectURI, errServerError, "session backend unavailable", req.State)
		return
	}
	if errors.Is(sessErr, sessions.ErrCurrentSessionExpired) {
		clearCookie(w, cookie.SessionProfile)
	}
	hint := computeAuthorizeHint(r.Context(), deps, req, client, active, now)
	switch hint.decision {
	case decisionLoginRequired:
		redirectError(w, r, req.RedirectURI, errLoginRequired, "user authentication is required", req.State)
	case decisionConsentRequired:
		redirectError(w, r, req.RedirectURI, errConsentRequired, "user consent is required", req.State)
	case decisionInteractionRequired:
		redirectError(w, r, req.RedirectURI, errInteractionRequired, "interaction is required", req.State)
	case decisionInteract:
		startInteraction(w, r, deps, req, client, active, hint.prompt)
	case decisionMint:
		mintAndRedirect(w, r, deps, req, client, active, hint.grant)
	}
}

// authorizeHint bundles the outcome of the decision matrix together with
// the data the chosen outcome consumes (the prompt name for an
// interaction, the existing grant for a silent mint).
type authorizeHint struct {
	decision authorizeDecision
	prompt   string
	grant    *store.Grant
}

// resolveSession reads the __Host-oidc_session cookie and asks the manager
// to resolve it. A missing cookie yields (nil, nil). Cookie failures are
// returned to the caller so it can clear the cookie when appropriate.
func resolveSession(r *http.Request, deps resolved) (*sessions.Active, error) {
	c, err := r.Cookie(cookie.SessionProfile.Name)
	if err != nil {
		// http.ErrNoCookie is the only documented error from r.Cookie;
		// any return value here is treated as "no session" because we
		// cannot decode what the browser did not send.
		return nil, nil //nolint:nilerr,nilnil // documented "no session" sentinel
	}
	if c == nil || c.Value == "" {
		return nil, nil //nolint:nilnil // documented "no session" sentinel
	}
	return deps.Sessions.Resolve(r.Context(), c.Value)
}

// computeAuthorizeHint runs the decision matrix described in
// docs/plans/002-product-design.md §A.12.2. The outcome depends on three
// orthogonal inputs: whether a session exists, whether the request forces
// a fresh login (prompt=login or max_age violation), and whether the
// existing grant covers the requested scope (or no grant exists at all).
func computeAuthorizeHint(
	ctx context.Context,
	deps resolved,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
	now time.Time,
) authorizeHint {
	state := buildHintState(ctx, deps, req, client, active, now)
	if state.promptNone {
		return decideHintPromptNone(state)
	}
	return decideHintInteractive(state)
}

// hintState collects the pre-computed flags that drive
// [computeAuthorizeHint]. It is a value type because the per-request flag
// set is small enough to copy and the readability win is worth more than
// the marginal allocation.
type hintState struct {
	hasSession  bool
	forceLogin  bool
	needConsent bool
	promptNone  bool
	selectAcct  bool
	existing    *store.Grant
}

// buildHintState computes the orthogonal flag set used by the decision
// matrix. The function is pure aside from the grant lookup; tests that
// need to exercise the matrix in isolation can construct hintState
// directly.
func buildHintState(
	ctx context.Context,
	deps resolved,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
	now time.Time,
) hintState {
	out := hintState{
		hasSession: active != nil,
		forceLogin: containsString(req.Prompt, interaction.PromptLogin),
		promptNone: containsString(req.Prompt, "none"),
		selectAcct: containsString(req.Prompt, interaction.PromptSelectAccount),
	}
	if !out.forceLogin && out.hasSession && req.MaxAge != nil {
		if now.UTC().Sub(active.Session.AuthTime.UTC()) > time.Duration(*req.MaxAge)*time.Second {
			out.forceLogin = true
		}
	}
	if out.hasSession {
		if g, err := deps.Grants.FindBySubjectClient(ctx, active.Session.Subject, client.ID); err == nil {
			out.existing = g
		}
	}
	out.needConsent = containsString(req.Prompt, interaction.PromptConsent) ||
		out.existing == nil ||
		!scopeIsSubset(req.Scope, out.existing.Scope)
	return out
}

// decideHintPromptNone resolves the matrix when prompt=none is present.
// The OIDC spec requires the OP to surface one of the *_required errors
// rather than start an interaction.
func decideHintPromptNone(s hintState) authorizeHint {
	switch {
	case !s.hasSession, s.forceLogin:
		return authorizeHint{decision: decisionLoginRequired}
	case s.needConsent:
		return authorizeHint{decision: decisionConsentRequired}
	case s.selectAcct:
		return authorizeHint{decision: decisionInteractionRequired}
	default:
		return authorizeHint{decision: decisionMint, grant: s.existing}
	}
}

// decideHintInteractive resolves the matrix when prompt!=none. The
// outcome is either a silent code mint or an interaction redirect.
func decideHintInteractive(s hintState) authorizeHint {
	switch {
	case !s.hasSession, s.forceLogin:
		return authorizeHint{decision: decisionInteract, prompt: interaction.PromptLogin}
	case s.needConsent:
		return authorizeHint{decision: decisionInteract, prompt: interaction.PromptConsent}
	default:
		return authorizeHint{decision: decisionMint, grant: s.existing}
	}
}

// startInteraction creates the persisted interaction record, sets the
// __Host-oidc_interaction cookie, and redirects the browser to
// /interaction/{uid}.
func startInteraction(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
	prompt string,
) {
	uid, err := newRandomB64(uidByteLength)
	if err != nil {
		redirectError(w, r, req.RedirectURI, errServerError, "could not allocate interaction id", req.State)
		return
	}
	now := deps.now().UTC()
	state := authorize.RequestState{Library: authorize.SnapshotFrom(req, now)}
	raw, err := authorize.MarshalState(state)
	if err != nil {
		redirectError(w, r, req.RedirectURI, errServerError, "could not marshal interaction state", req.State)
		return
	}
	rec := &store.Interaction{
		ID:        uid,
		ClientID:  client.ID,
		Step:      prompt,
		RawState:  raw,
		ExpiresAt: now.Add(deps.InteractionTTL),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := deps.Interactions.Save(r.Context(), rec); err != nil {
		redirectError(w, r, req.RedirectURI, errServerError, "could not persist interaction", req.State)
		return
	}
	if err := setInteractionCookie(w, deps, uid); err != nil {
		redirectError(w, r, req.RedirectURI, errServerError, "could not set interaction cookie", req.State)
		return
	}
	// Inform the Driver so it can pre-render UI state. Errors from the
	// Driver are intentionally swallowed: the interaction record is
	// already persisted, and the SPA will get a fresh Offer call on the
	// matching GET.
	_, _ = deps.Driver.Offer(r.Context(), interaction.Request{
		UID:            uid,
		ClientID:       client.ID,
		CurrentSubject: currentSubject(active),
	})
	stampNoStore(w)
	target := deps.InteractionPath + "/" + uid
	http.Redirect(w, r, target, http.StatusFound)
}

// currentSubject returns the active session's subject or empty when there
// is no session. The helper exists so the call sites stay free of nil
// handling boilerplate.
func currentSubject(active *sessions.Active) string {
	if active == nil || active.Session == nil {
		return ""
	}
	return active.Session.Subject
}

// mintAndRedirect persists a fresh authorization code bound to the existing
// grant and redirects the browser to redirect_uri?code=...&state=....
func mintAndRedirect(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
	existing *store.Grant,
) {
	if active == nil || existing == nil {
		// Defensive: the dispatcher only reaches mintAndRedirect when
		// both are non-nil. Surface a server_error redirect so a
		// future regression is observable.
		redirectError(w, r, req.RedirectURI, errServerError, "missing session or grant for silent mint", req.State)
		return
	}
	codeID, err := newRandomB64(codeByteLength)
	if err != nil {
		redirectError(w, r, req.RedirectURI, errServerError, "could not allocate code", req.State)
		return
	}
	now := deps.now().UTC()
	rec := &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             active.Session.Subject,
		GrantID:             existing.ID,
		RedirectURI:         req.RedirectURI,
		Scope:               append([]string(nil), req.Scope...),
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
		State:               req.State,
		ExpiresAt:           now.Add(deps.AuthCodeTTL),
		CreatedAt:           now,
	}
	if err := deps.Codes.Save(r.Context(), rec); err != nil {
		redirectError(w, r, req.RedirectURI, errServerError, "could not persist authorization code", req.State)
		return
	}
	stampNoStore(w)
	http.Redirect(w, r, buildSuccessRedirect(req.RedirectURI, codeID, req.State), http.StatusFound)
}

// buildSuccessRedirect composes the success redirect target. It is split
// out so it can be tested without invoking the HTTP machinery.
func buildSuccessRedirect(redirectURI, code, state string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		// The validator already accepted the redirect_uri, so a parse
		// failure here is a programmer bug. Return the original URI
		// unchanged; the caller emits a redirect either way and the
		// audit log will surface the malformed value.
		return redirectURI
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// setInteractionCookie seals uid under the interaction AAD and writes it as
// the __Host-oidc_interaction cookie.
func setInteractionCookie(w http.ResponseWriter, deps resolved, uid string) error {
	value, err := deps.CookieCodec.Seal([]byte(uid), []byte(interactionAAD))
	if err != nil {
		return fmt.Errorf("authorizeendpoint: seal interaction cookie: %w", err)
	}
	c, err := cookie.Build(cookie.InteractionProfile, value)
	if err != nil {
		return fmt.Errorf("authorizeendpoint: build interaction cookie: %w", err)
	}
	http.SetCookie(w, c)
	return nil
}

// clearCookie writes a Set-Cookie header that instructs the browser to
// remove the named cookie. Errors during construction are swallowed: a
// failure here is a programming bug (the profile is a package constant)
// and surfacing it would mask the original response we were emitting.
func clearCookie(w http.ResponseWriter, profile cookie.Profile) {
	if c, err := cookie.Clear(profile); err == nil {
		http.SetCookie(w, c)
	}
}

// newRandomB64 returns a base64url-no-pad encoded random identifier of the
// supplied byte length.
func newRandomB64(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("authorizeendpoint: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
