package authorizeendpoint

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/consent"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/proxy"
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
		renderBrowserError(w, r, deps.Driver, http.StatusMethodNotAllowed, errInvalidRequest, "method not allowed", "")
		return
	}
	if r.Method == http.MethodPost {
		if !isFormContent(r.Header.Get("Content-Type")) {
			renderBrowserError(w, r, deps.Driver, http.StatusBadRequest, errInvalidRequest,
				"content-type must be application/x-www-form-urlencoded", "")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxAuthorizeFormBytes)
	}
	values, err := extractAuthorizeValues(r)
	if err != nil {
		writeAuthorizeParseError(w, r, deps, err)
		return
	}
	req, ok := resolveAuthorizeRequest(w, r, deps, values)
	if !ok {
		return
	}
	client, err := deps.Clients.GetClient(r.Context(), req.ClientID)
	if err != nil {
		// Treat a missing or unknown client as an unrecoverable
		// invalid_request: redirect_uri is not yet trusted, so the
		// response MUST stay pre-redirect (HTML for a browser, JSON
		// for an API caller).
		renderBrowserError(w, r, deps.Driver, http.StatusBadRequest, errInvalidRequest, "client_id is not registered", req.State)
		return
	}
	applyClientAuthorizeDefaults(req, client)
	if err := req.Validate(client, deps.Scopes, authorize.Policy{
		PKCERequired:         deps.RequirePKCE,
		NonceRequired:        deps.RequireNonce,
		StateOrNonceRequired: deps.RequireStateOrNonce,
		OpenIDScopeOptional:  deps.OpenIDScopeOptional,
	}); err != nil {
		writeAuthorizeValidationError(w, r, req, deps, err)
		return
	}
	if jarmFeatureRequested(req) && deps.JARM == nil {
		// The request asked for a JARM mode but the OP did not opt in
		// to the feature. Surface "unsupported_response_mode" via the
		// legacy redirect — JARM cannot be used to convey "JARM is not
		// supported by this OP". emitAuthorizeError implements the same
		// fallback for the post-Validate paths.
		emitAuthorizeError(w, r, deps, req, errUnsupportedResponseMode,
			"response_mode is not supported by this OP")
		return
	}
	if jarmModeMissing(deps, req) {
		// The active profile (FAPI 2.0 Message Signing §5.5) requires
		// every authorize response to be JARM-wrapped, but this request
		// did not opt into a JARM response_mode. Surface
		// "unsupported_response_mode" via the legacy redirect — the
		// non-JARM mode the request asked for is the one the profile
		// forbids, and JARM cannot be used to convey "JARM is not in
		// use yet".
		emitAuthorizeError(w, r, deps, req, errUnsupportedResponseMode,
			`response_mode is required by the active profile (use "jwt", "query.jwt", "fragment.jwt", or "form_post.jwt")`)
		return
	}
	dispatchAuthorize(w, r, deps, req, client)
}

func applyClientAuthorizeDefaults(req *authorize.Request, client *store.Client) {
	if req == nil || client == nil {
		return
	}
	if req.MaxAge == nil && client.DefaultMaxAge != nil {
		v := *client.DefaultMaxAge
		req.MaxAge = &v
	}
	if len(req.ACRValues) == 0 && len(client.DefaultACRValues) > 0 {
		req.ACRValues = append([]string(nil), client.DefaultACRValues...)
	}
}

// extractAuthorizeValues returns the [url.Values] the request carries,
// reading the URL query for GET and the form body for POST. It mirrors
// the unexported helper inside [internal/authorize] so the authorize
// endpoint can inspect the values once before deciding whether to honour
// a request_uri (PAR) or parse the inline parameters.
func extractAuthorizeValues(r *http.Request) (url.Values, error) {
	if r == nil {
		return nil, authorize.ErrClientIDRequired
	}
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			return nil, err
		}
		return r.PostForm, nil
	}
	return r.URL.Query(), nil
}

// resolveAuthorizeRequest is the parse + PAR / JAR-consumption gate.
// The order is:
//  1. PAR: a "request_uri" matching the urn:ietf:params:oauth:request_uri:
//     prefix is consumed from the persisted record (RFC 9126 §2.3) and
//     every other parameter except client_id is ignored.
//  2. JAR: a "request" parameter is verified and merged onto the wire
//     values per RFC 9101 §6.1; the merged values are then re-parsed.
//     A "request_uri" that does NOT match the PAR URN prefix is
//     rejected by [authorize.ParseValues] with
//     [authorize.ErrInvalidRequestURI] — the library does not
//     implement the RFC 9101 §5.2.2 generic-URI fetch, only the PAR
//     form, so the JAR-by-URI surface is intentionally closed.
//  3. Bare wire form: the values feed straight to [authorize.ParseValues].
//
// The returned bool reports whether processing should continue: false
// means the function already wrote the response.
func resolveAuthorizeRequest(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	values url.Values,
) (*authorize.Request, bool) {
	queryClientID := values.Get("client_id")
	if parReq, handled := resolvePARIfNeeded(r.Context(), w, r, deps, queryClientID, values); handled {
		return nil, false
	} else if parReq != nil {
		return parReq, true
	}
	if deps.RequirePAR {
		// PAR consumption did not fire (no urn:ietf:params:oauth:request_uri:
		// prefix), and the active profile mandates PAR. Reject before
		// JAR / bare-form processing — under FAPI 2.0 §5.3.1 a request
		// that omits the request_uri is invalid_request regardless of
		// whether it carries a JAR request_object.
		renderAuthorizeError(w, r, deps, errPARRequired)
		return nil, false
	}
	merged, jarHandled, jarStop := resolveJARRequestIfNeeded(r.Context(), w, deps, queryClientID, values)
	if jarStop {
		return nil, false
	}
	if jarHandled {
		values = merged
	}
	req, err := authorize.ParseValues(values)
	if err != nil {
		writeAuthorizeParseError(w, r, deps, err)
		return nil, false
	}
	if !deps.ClaimsParameterEnabled {
		// op.WithClaimsParameterSupported(false): drop the parsed
		// payload so the snapshot, the persisted grant, and the
		// downstream id_token / userinfo projection all behave as if
		// the parameter had been silently ignored. The wire-level
		// rejection of a malformed payload still fires above so a
		// hostile RP cannot probe the OP through claims-shaped junk.
		req.Claims = nil
	}
	return req, true
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
	return endpointsupport.IsFormContent(ct)
}

// writeAuthorizeParseError handles errors emitted by [authorize.ParseRequest].
// Every error at this stage is pre-redirect-URI: there is no trusted
// redirect target, so the response stays pre-redirect (HTML for a
// browser, JSON for an API caller).
func writeAuthorizeParseError(w http.ResponseWriter, r *http.Request, deps resolved, err error) {
	var ae *authorize.Error
	if errors.As(err, &ae) {
		renderBrowserError(w, r, deps.Driver, http.StatusBadRequest, ae.Code, ae.Description, "")
		return
	}
	renderBrowserError(w, r, deps.Driver, http.StatusBadRequest, errInvalidRequest, "request could not be parsed", "")
}

// writeAuthorizeValidationError translates a [authorize.Validate] failure
// into either a redirect or a pre-redirect envelope, depending on
// whether the redirect target has been trusted yet. JARM-mode requests
// get the signed-JWT envelope automatically via [emitAuthorizeError].
func writeAuthorizeValidationError(w http.ResponseWriter, r *http.Request, req *authorize.Request, deps resolved, err error) {
	var ae *authorize.Error
	if !errors.As(err, &ae) {
		renderBrowserError(w, r, deps.Driver, http.StatusInternalServerError, errServerError, "", req.State)
		return
	}
	if !authorize.IsRedirectSafe(err) {
		renderBrowserError(w, r, deps.Driver, http.StatusBadRequest, ae.Code, ae.Description, req.State)
		return
	}
	emitAuthorizeError(w, r, deps, req, ae.Code, ae.Description)
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
		emitAuthorizeError(w, r, deps, req, errServerError, "session backend unavailable")
		return
	}
	if errors.Is(sessErr, sessions.ErrCurrentSessionExpired) {
		clearCookie(w, cookie.SessionProfile)
	}
	hint := computeAuthorizeHint(r.Context(), deps, req, client, active, now)
	switch hint.decision {
	case decisionLoginRequired:
		emitAuthorizeError(w, r, deps, req, errLoginRequired, "user authentication is required")
	case decisionConsentRequired:
		emitAuthorizeError(w, r, deps, req, errConsentRequired, "user consent is required")
	case decisionInteractionRequired:
		emitAuthorizeError(w, r, deps, req, errInteractionRequired, "interaction is required")
	case decisionInteract:
		startInteraction(w, r, deps, req, client, active, hint.grant)
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
// 02-product-design.md §A.12.2. The outcome depends on three
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
// rather than start an interaction. The strict prompt validator
// (request.Validate / validatePrompt) already rejected prompt=none
// combined with any other prompt as invalid_request, so this branch
// only runs with prompt=none alone.
func decideHintPromptNone(s hintState) authorizeHint {
	switch {
	case !s.hasSession, s.forceLogin:
		return authorizeHint{decision: decisionLoginRequired}
	case s.needConsent:
		return authorizeHint{decision: decisionConsentRequired}
	default:
		return authorizeHint{decision: decisionMint, grant: s.existing}
	}
}

// decideHintInteractive resolves the matrix when prompt!=none. The
// outcome is either a silent code mint or an interaction redirect.
// The existing grant is forwarded on the interact path so
// [startInteraction] can pre-mark the consent step as already covered
// when the cached grant subsumes the requested scope.
//
// prompt=select_account on a request with an active session is
// routed to the chooser interaction. The hint records the prompt
// as [interaction.PromptSelectAccount] so [startInteraction] knows
// to register the chooser; consent still runs after the chooser
// if the picked subject's grant does not cover the requested
// scope.
func decideHintInteractive(s hintState) authorizeHint {
	switch {
	case !s.hasSession, s.forceLogin:
		return authorizeHint{decision: decisionInteract, prompt: interaction.PromptLogin, grant: s.existing}
	case s.selectAcct:
		return authorizeHint{decision: decisionInteract, prompt: interaction.PromptSelectAccount, grant: s.existing}
	case s.needConsent:
		return authorizeHint{decision: decisionInteract, prompt: interaction.PromptConsent, grant: s.existing}
	default:
		return authorizeHint{decision: decisionMint, grant: s.existing}
	}
}

// startInteraction creates the persisted interaction record with a
// freshly-initialised orchestrator [authn.State], sets the
// __Host-oidc_interaction cookie, and redirects the browser to
// /interaction/{uid}. The orchestrator runs on the first GET and
// emits the initial prompt.
// existing is the grant the dispatcher resolved for (subject,
// client_id), or nil when no cached grant covers this attempt. When
// existing is non-nil and already covers the requested scope, the
// helper pre-marks the built-in consent interaction as already run
// so the user is not prompted to re-confirm scopes they have already
// granted.
func startInteraction(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
	existing *store.Grant,
) {
	if deps.Authn == nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "interaction is not configured")
		return
	}
	uid, err := newRandomB64(uidByteLength)
	if err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not allocate interaction id")
		return
	}
	now := deps.now().UTC()
	willRunChooser := containsString(req.Prompt, interaction.PromptSelectAccount) && active != nil
	interactionsRun := map[string]bool{}
	// When the chooser will run, the picked subject may differ
	// from the cookie-resolved one. The grant we looked up
	// (against the current subject) does not authoritatively cover
	// the picked subject's scope set, so do NOT pre-mark consent
	// as already run. Consent re-evaluates after the chooser binds
	// the picked subject.
	if !willRunChooser && existing != nil && scopeIsSubset(req.Scope, existing.Scope) {
		interactionsRun[consent.Name] = true
	}
	chooserGroupID := ""
	if willRunChooser && active.Session != nil {
		chooserGroupID = active.Session.ChooserGroupID
	}
	authnState := authn.State{
		InteractionUID:  uid,
		ClientID:        client.ID,
		Client:          projectClientView(client),
		Subject:         currentSubject(active),
		RemoteIP:        clientIPFromRequest(r, deps),
		UserAgent:       truncateUserAgent(r.UserAgent()),
		AuthTime:        now,
		ActiveFactorIdx: -1,
		Phase:           authn.PhaseBeforeAuthn,
		InteractionsRun: interactionsRun,
		RequestedScopes: append([]string(nil), req.Scope...),
		ACRValues:       append([]string(nil), req.ACRValues...),
		ChooserGroupID:  chooserGroupID,
	}
	authnRaw, err := encodeAuthnState(authnState)
	if err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not marshal interaction state")
		return
	}
	state := authorize.RequestState{
		Library: authorize.SnapshotFrom(req, now),
		Authn:   authnRaw,
	}
	raw, err := authorize.MarshalState(state)
	if err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not marshal interaction state")
		return
	}
	rec := &store.Interaction{
		ID:        uid,
		ClientID:  client.ID,
		RawState:  raw,
		ExpiresAt: now.Add(deps.InteractionTTL),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := deps.Interactions.Save(r.Context(), rec); err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not persist interaction")
		return
	}
	if err := setInteractionCookie(w, deps, uid); err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not set interaction cookie")
		return
	}
	stampNoStore(w)
	target := deps.authorizeRedirectBase() + "/" + uid
	http.Redirect(w, r, target, http.StatusFound)
}

// userAgentMaxLen caps the [http.Request] User-Agent string the
// orchestrator records on the chain state. The cap mirrors the
// length internal/sessions uses for its session record so the values
// remain comparable across the HTTP layer.
const userAgentMaxLen = 512

// truncateUserAgent enforces the [userAgentMaxLen] cap. Empty input
// passes through; over-long strings are sliced byte-wise.
func truncateUserAgent(ua string) string {
	if len(ua) <= userAgentMaxLen {
		return ua
	}
	return ua[:userAgentMaxLen]
}

// clientIPFromRequest returns the [netip.Addr] the OP considers
// authoritative for r. The function delegates to [proxy.Resolve],
// which:
//
//   - when [Deps.ProxyTrust] is configured AND r.RemoteAddr lies
//     inside a trusted CIDR: honours X-Forwarded-For per RFC 7239 §5.2
//     (first non-trusted hop wins, preventing a client from forging
//     its IP by writing fake values to the left of the chain);
//   - otherwise: falls back to r.RemoteAddr so a hostile client
//     cannot spoof its source IP merely by setting the header.
//
// The brute-force counter and audit-log fields downstream consume the
// returned value, so honouring the forwarded header behind a trusted
// proxy closes the fingerprinting gap H-C5 surfaced (without the
// trust every authenticated request would attribute to the proxy IP,
// hiding the real client from the rate limiter).
func clientIPFromRequest(r *http.Request, deps resolved) netip.Addr {
	res := proxy.Resolve(r, deps.ProxyTrust)
	return res.ClientIP
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

// projectClientView builds the read-only template projection of
// [store.Client]. The function intentionally ships the field set
// fixed by [interaction.ClientView] — adding a field here is a
// deliberate widening of the template trust boundary and requires
// its own ADR.
func projectClientView(c *store.Client) interaction.ClientView {
	if c == nil {
		return interaction.ClientView{}
	}
	return interaction.ClientView{
		ClientID:  c.ID,
		Name:      c.ClientName,
		LogoURL:   c.LogoURI,
		ClientURI: c.ClientURI,
		PolicyURI: c.PolicyURI,
		TosURI:    c.TosURI,
	}
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
		emitAuthorizeError(w, r, deps, req, errServerError, "missing session or grant for silent mint")
		return
	}
	if err := consumePARIfNeeded(r.Context(), deps, req); err != nil {
		emitAuthorizeError(w, r, deps, req, errAccessDenied, "request_uri is no longer valid")
		return
	}
	codeID, err := newRandomB64(codeByteLength)
	if err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not allocate code")
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
		Resource:            req.Resource,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		Nonce:               req.Nonce,
		State:               req.State,
		DPoPJKT:             req.DPoPJKT,
		ExpiresAt:           now.Add(deps.AuthCodeTTL),
		CreatedAt:           now,
	}
	if err := deps.Codes.Save(r.Context(), rec); err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not persist authorization code")
		return
	}
	emitAuthorizeSuccess(w, r, deps, req, codeID)
}

// buildSuccessRedirect composes the success redirect target. It is split
// out so it can be tested without invoking the HTTP machinery.
func buildSuccessRedirect(redirectURI, code, state, issuer string) string {
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
	if issuer != "" {
		// RFC 9207 §2.3: every authorization response carries "iss"
		// equal to the OP's discovery issuer. Defense-in-depth against
		// the mix-up attack class; FAPI 2.0 §5.3.2.2 mandates it.
		q.Set("iss", issuer)
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
