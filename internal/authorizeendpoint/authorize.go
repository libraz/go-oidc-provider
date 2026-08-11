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
	"reflect"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/consent"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/internal/proxy"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// opAuditConsentGrantedFirstParty mirrors the public
// op.AuditConsentGrantedFirstParty constant. The internal package
// cannot import op (one-way import graph), so the value is duplicated
// here and pinned by TestAuditEvent_FirstPartyMirror in
// op/audit_test.go.
const opAuditConsentGrantedFirstParty = string(auditevent.AuditConsentGrantedFirstParty)

const (
	opAuditCodeIssued     = string(auditevent.AuditCodeIssued)
	opAuditConsentGranted = string(auditevent.AuditConsentGranted)
	opAuditSessionCreated = string(auditevent.AuditSessionCreated)
)

// serveAuthorize is the request-scoped entry point for /authorize. It runs
// the validator from internal/authorize, resolves the active session,
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
		endpointsupport.LimitFormBody(w, r)
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
	if err == nil && client == nil {
		// A nil client alongside a nil error violates the store contract;
		// a client the backend cannot produce is not a registered one.
		err = store.ErrNotFound
	}
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
	if !validateRequestExtensions(w, r, deps, req, client) {
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

// validateRequestExtensions runs the request gates that sit between a
// successful [authorize.Request.Validate] and dispatch: RFC 9396
// authorization_details, the Grant Management draft parameters, and the
// RFC 9449 §10.1 "dpop_jkt" commitment.
//
// The rules themselves live in [authorize.Request.ValidateExtensions],
// shared verbatim with the pushed-authorization-request endpoint so the
// two consecutive gates on the same request cannot disagree. This
// function only renders: the checks run after [authorize.Request.Validate]
// so redirect_uri has been matched against the client's registration and
// the rejection can take the endpoint's normal channel (JARM / form_post
// / redirect) rather than a pre-redirect first-party page.
//
// Returns false when it wrote the response; the caller then stops.
func validateRequestExtensions(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	req *authorize.Request,
	client *store.Client,
) bool {
	rejection := req.ValidateExtensions(r.Context(), client, authorize.ExtensionPolicy{
		AuthorizationDetailTypes:      deps.AuthorizationDetailTypes,
		GrantManagementEnabled:        deps.GrantManagementEnabled,
		GrantManagementActions:        deps.GrantManagementActions,
		GrantManagementActionRequired: deps.GrantManagementActionRequired,
		DPoPEnabled:                   deps.DPoPEnabled,
	})
	if rejection == nil {
		return true
	}
	emitAuthorizeError(w, r, deps, req, rejection.Code, rejection.Description)
	return false
}

// Grant Management draft action wire strings honoured at /authorize.
// query / revoke are endpoint-only operations and are rejected by the
// shared gate. The names alias the shared constants so the grant
// emission path here and the request gate cannot drift apart.
const (
	gmActionCreate  = authorize.GrantManagementActionCreate
	gmActionReplace = authorize.GrantManagementActionReplace
	gmActionMerge   = authorize.GrantManagementActionMerge
)

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
// the unexported helper inside internal/authorize so the authorize
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
	merged, jarHandled, jarStop := resolveJARRequestIfNeeded(w, r, deps, queryClientID, values)
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
// helper in internal/tokenendpoint so the two endpoints stay aligned.
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
	if errors.Is(sessErr, sessions.ErrCurrentSessionExpired) || errors.Is(sessErr, sessions.ErrCookieInvalid) {
		// Clear the session cookie on BOTH a decodable-but-expired session
		// and a tampered/undecodable cookie. Without the ErrCookieInvalid
		// arm a corrupted cookie is treated as "no session" but left in the
		// browser, so every subsequent request re-sends the garbage value
		// and re-fails the decode; expiring it lets the browser start clean.
		clearCookie(w, cookie.SessionProfile)
	}
	hint, err := computeAuthorizeHint(r.Context(), deps, req, client, active, now)
	if err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "grant backend unavailable")
		return
	}
	if firstPartyShouldSkipConsent(r, hint, req, client, active, deps) {
		hint = applyFirstPartySkip(deps, req, client, active)
	}
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
		mintAndRedirect(w, r, deps, req, client, active, hint)
	}
}

// firstPartyShouldSkipConsent reports whether the dispatcher's pending
// outcome (a consent prompt or a prompt=none consent_required error)
// should instead be auto-resolved through the first-party skip path
// configured by [op.WithFirstPartyClients]. The four preconditions:
//
//  1. The client_id appears in [Deps.FirstPartyClients]. The wiring
//     layer materialises this set only for static / admin clients;
//     dynamic-source clients (RFC 7591) are excluded structurally.
//  2. The pending decision would otherwise prompt the user for
//     consent — either an interactive consent prompt or the
//     prompt=none consent_required error. Login / chooser / silent-
//     mint outcomes pass through unchanged.
//  3. An active session exists. With no session there is no subject
//     to bind the grant to; the first-party skip never invents one.
//  4. The request did NOT carry prompt=consent. An RP that explicitly
//     asks for re-consent always gets the prompt; the first-party
//     flag is the OP's posture, not the RP's override.
//
// The [store.Client.Source] guard is enforced by the wiring layer
// (see [firstPartyClientSet]); this helper trusts that contract.
func firstPartyShouldSkipConsent(
	r *http.Request,
	hint authorizeHint,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
	deps resolved,
) bool {
	if active == nil || client == nil {
		return false
	}
	if !deps.isFirstPartyClient(client.ID) {
		return false
	}
	if !firstPartyAutoGrantRequestTrusted(r, req.RedirectURI) {
		return false
	}
	if containsString(req.Prompt, interaction.PromptConsent) {
		return false
	}
	if oidcscope.ContainsOfflineAccess(req.Scope) {
		return false
	}
	if req.GrantManagementAction != "" {
		// A Grant Management mutation always gets an explicit consent
		// ceremony; the first-party auto-grant never silently
		// creates / replaces / merges a managed grant.
		return false
	}
	if len(req.AuthorizationDetails) > 0 {
		// RFC 9396 authorization_details are rich, consent-bearing
		// authorizations (e.g. a payment_initiation amount/payee). The
		// first-party auto-grant never silently grants them; the user
		// always sees an explicit consent ceremony.
		return false
	}
	switch hint.decision {
	case decisionInteract:
		return hint.prompt == interaction.PromptConsent
	case decisionConsentRequired:
		return true
	default:
		return false
	}
}

func firstPartyAutoGrantRequestTrusted(r *http.Request, redirectURI string) bool {
	if r == nil {
		return false
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin":
		return true
	case "same-site":
		return firstPartySameSiteOriginMatchesRedirect(r, redirectURI)
	default:
		return false
	}
}

func firstPartySameSiteOriginMatchesRedirect(r *http.Request, redirectURI string) bool {
	redirectOrigin, ok := originFromRawURL(redirectURI)
	if !ok {
		return false
	}
	for _, raw := range []string{r.Header.Get("Origin"), r.Header.Get("Referer")} {
		if raw == "" {
			continue
		}
		if origin, ok := originFromRawURL(raw); ok && origin == redirectOrigin {
			return true
		}
	}
	return false
}

func originFromRawURL(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", false
	}
	return u.Scheme + "://" + u.Host, true
}

// applyFirstPartySkip plans the grant the dispatcher would otherwise have
// asked the user to confirm and rewrites the hint so the switch in
// [dispatchAuthorize] mints a code silently. The grant is deliberately not
// written here: mintAndRedirect commits it together with PAR consumption and
// authorization-code persistence.
//
// The grant subject is the raw OP-internal identifier the session
// carries, mirroring what interaction.go persists at the end of an
// interactive consent ceremony and matching [store.Grant.Subject]'s
// contract. Projection through [op.SubjectGenerator] happens per client
// at egress — id_token, JWT access token, userinfo, introspection —
// never at persistence, so that one grant serves every client the
// subject authorizes and a salt rotation changes what is emitted
// without rewriting stored rows. Storing a projected value here would
// be projected a second time downstream and would also break the
// (Subject, ClientID) grant lookup, which is keyed on the raw subject.
// The authorize endpoint holds no projector, which is what keeps the
// mistake from being reachable by accident.
//
// AuthTime / ACR / AMR come from [sessionAuthContext] so the grant
// reflects the authentication the request was served from, the same
// context [resolveSilentGrant] stamps on the silent-mint path.
func applyFirstPartySkip(
	deps resolved,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
) authorizeHint {
	authCtx := sessionAuthContext(active)
	planned := &grantUpsert{
		Subject:              active.Session.Subject,
		ClientID:             client.ID,
		Scope:                append([]string(nil), req.Scope...),
		AuthTime:             authCtx.AuthTime,
		ACR:                  authCtx.ACR,
		AMR:                  authCtx.AMR,
		Claims:               req.Claims,
		AuthorizationDetails: req.AuthorizationDetails,
		Now:                  deps.now(),
	}
	return authorizeHint{decision: decisionMint, autoGrant: planned}
}

// authorizeHint bundles the outcome of the decision matrix together with
// the data the chosen outcome consumes (the prompt name for an
// interaction, the existing grant for a silent mint).
type authorizeHint struct {
	decision  authorizeDecision
	prompt    string
	grant     *store.Grant
	autoGrant *grantUpsert
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
	active, err := deps.Sessions.Resolve(r.Context(), c.Value)
	if err != nil {
		return nil, err
	}
	if err := deps.Sessions.Touch(r.Context(), active.Session.ID); err != nil {
		return nil, err
	}
	return active, nil
}

// computeAuthorizeHint runs the authorize decision matrix that picks
// between "reuse the session", "re-authenticate" and "prompt for
// consent". The outcome depends on three
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
) (authorizeHint, error) {
	state, err := buildHintState(ctx, deps, req, client, active, now)
	if err != nil {
		return authorizeHint{}, err
	}
	if state.promptNone {
		return decideHintPromptNone(state), nil
	}
	return decideHintInteractive(state), nil
}

// hintState collects the pre-computed flags that drive
// [computeAuthorizeHint]. It is a value type because the per-request flag
// set is small enough to copy and the readability win is worth more than
// the marginal allocation.
type hintState struct {
	hasSession     bool
	forceLogin     bool
	acrUnsatisfied bool
	needConsent    bool
	promptNone     bool
	selectAcct     bool
	existing       *store.Grant
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
) (hintState, error) {
	out := hintState{
		hasSession: active != nil,
		forceLogin: containsString(req.Prompt, interaction.PromptLogin),
		promptNone: containsString(req.Prompt, "none"),
		selectAcct: containsString(req.Prompt, interaction.PromptSelectAccount),
	}
	if !out.forceLogin && out.hasSession && req.MaxAge != nil {
		if *req.MaxAge == 0 || now.UTC().Sub(active.Session.AuthTime.UTC()) > time.Duration(*req.MaxAge)*time.Second {
			out.forceLogin = true
		}
	}
	if out.hasSession {
		out.acrUnsatisfied = acrUnsatisfiedByRequest(active.Session.ACR, req)
	}
	if out.hasSession {
		g, err := findGrantForConsentDecision(
			ctx,
			deps.Grants,
			active.Session.Subject,
			client.ID,
		)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return hintState{}, err
		}
		if err == nil {
			out.existing = g
		}
	}
	out.needConsent = !consentAlreadyCovered(req, out.existing)
	return out, nil
}

func findGrantForConsentDecision(
	ctx context.Context,
	grants store.GrantStore,
	subject,
	clientID string,
) (*store.Grant, error) {
	grant, err := grants.FindBySubjectClient(ctx, subject, clientID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("authorizeendpoint: find grant for consent decision: %w", err)
	}
	if grant == nil {
		return nil, errors.New("authorizeendpoint: grant lookup returned nil record")
	}
	if grant.ID == "" || grant.Subject != subject || grant.ClientID != clientID {
		return nil, errors.New("authorizeendpoint: grant lookup returned mismatched record")
	}
	return grant, nil
}

// consentAlreadyCovered reports whether the cached grant fully covers
// what this request would ask the user to approve. It is the single
// predicate behind both consent gates: the dispatcher's needConsent
// flag and the pre-marking of the built-in consent interaction in
// [initialInteractionsRun]. Keeping one predicate is what stops the
// two from disagreeing — a request the matrix routes to a consent
// prompt must never arrive at the orchestrator with consent already
// marked as run, which would hand the RP a code without a ceremony.
//
// Coverage requires all of:
//
//   - The RP did not ask for re-consent (prompt=consent is the RP's
//     explicit override and is never satisfied by a cached grant).
//   - No Grant Management action: create / replace / merge each mutate
//     a specific grant, and the mutation plus its ownership check run
//     in upsertGrant on the interaction path.
//   - A grant exists whose scope set subsumes the requested scope.
//   - Every requested RFC 9396 authorization_details element is already
//     on that grant.
func consentAlreadyCovered(req *authorize.Request, existing *store.Grant) bool {
	if req == nil || existing == nil {
		return false
	}
	if containsString(req.Prompt, interaction.PromptConsent) {
		return false
	}
	if req.GrantManagementAction != "" {
		return false
	}
	return scopeIsSubset(req.Scope, existing.Scope) &&
		authorizationDetailsCovered(req.AuthorizationDetails, existing)
}

// authorizationDetailsCovered reports whether every requested RFC 9396
// authorization_details element is already present on the grant. The
// requested details are consent-bearing rich authorizations, so a request
// that introduces a new element must run through consent (where the
// interaction path persists it onto the grant) rather than silent-mint a
// code against a grant whose details do not match — which would otherwise
// either drop the requested detail or grant it without the user seeing it.
func authorizationDetailsCovered(requested []map[string]any, grant *store.Grant) bool {
	if len(requested) == 0 {
		return true
	}
	if grant == nil {
		return false
	}
	for _, want := range requested {
		found := false
		for _, have := range grant.AuthorizationDetails {
			if reflect.DeepEqual(have, want) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// acrSatisfiedBySession reports whether the existing session's recorded
// ACR is one of the acr_values the request asked for. RFC 9470 step-up:
// when an RP requests one or more acr_values and the current session's
// authentication context is not among them, the OP must re-authenticate
// to reach a requested context rather than silently reuse the weaker
// session.
//
// The predicate is exact string membership, deliberately not routed
// through [op.ACRPolicy]: that seam resolves the id_token acr/amr at
// issuance from the AAL a fresh ceremony reached, but an existing session
// carries only its recorded ACR string (no AAL), and the lax default
// policy treats any AAL >= 1 as satisfying any acr — which would make
// step-up a no-op. Membership is the conservative reading: a session ACR
// outside the requested set (an empty ACR included) is unsatisfied and
// forces re-authentication. ACR hierarchies (a stronger session ACR
// subsuming a weaker request) are intentionally not modelled; erring
// toward an extra prompt is the safe direction.
func acrSatisfiedBySession(sessionACR string, requested []string) bool {
	if sessionACR == "" {
		return false
	}
	return containsString(requested, sessionACR)
}

func acrUnsatisfiedByRequest(sessionACR string, req *authorize.Request) bool {
	if req == nil {
		return false
	}
	if len(req.ACRValues) > 0 && !acrSatisfiedBySession(sessionACR, req.ACRValues) {
		return true
	}
	spec, ok := req.Claims.IDTokenSpec("acr")
	if !ok || !spec.Essential {
		return false
	}
	if len(spec.Values) == 0 && spec.Value == nil {
		return sessionACR == ""
	}
	if value, ok := spec.Value.(string); ok && sessionACR == value {
		return false
	}
	for _, candidate := range spec.Values {
		if value, ok := candidate.(string); ok && sessionACR == value {
			return false
		}
	}
	return true
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
	case s.acrUnsatisfied:
		// RFC 9470 step-up under prompt=none: the session exists but its
		// authentication context is too weak for the requested acr_values,
		// and prompt=none forbids an interaction. §9① resolves this to
		// interaction_required (distinct from the login_required that a
		// max_age expiry or absent session yields).
		return authorizeHint{decision: decisionInteractionRequired}
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
	case !s.hasSession, s.forceLogin, s.acrUnsatisfied:
		// acrUnsatisfied joins the login branch: an RFC 9470 step-up runs
		// the authn chain again to reach the requested acr_values (already
		// carried on the interaction state), and terminateInteraction
		// re-stamps the resolved acr / auth_time onto the session + grant.
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
	authnState := initialAuthnState(r, deps, req, client, active, existing, uid, now)
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

func initialAuthnState(
	r *http.Request,
	deps resolved,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
	existing *store.Grant,
	uid string,
	now time.Time,
) authn.State {
	willRunChooser := containsString(req.Prompt, interaction.PromptSelectAccount) && active != nil
	return authn.State{
		InteractionUID:           uid,
		ClientID:                 client.ID,
		Client:                   projectClientView(client),
		Subject:                  currentSubject(active),
		RemoteIP:                 clientIPFromRequest(r, deps),
		UserAgent:                truncateUserAgent(r.UserAgent()),
		AuthTime:                 now,
		ActiveFactorIdx:          -1,
		Phase:                    authn.PhaseBeforeAuthn,
		InteractionsRun:          initialInteractionsRun(req, existing, willRunChooser),
		RequestedScopes:          append([]string(nil), req.Scope...),
		ACRValues:                requestedACRValues(req),
		ChooserGroupID:           activeChooserGroupID(active, willRunChooser),
		ChooserAddAccount:        chooserAddAccountRequested(req, active),
		ChooserAddAccountGroupID: chooserAddAccountGroupID(req, active),
	}
}

func initialInteractionsRun(req *authorize.Request, existing *store.Grant, willRunChooser bool) map[string]bool {
	interactionsRun := map[string]bool{}
	// When the chooser will run, the picked subject may differ from the
	// cookie-resolved one. The grant we looked up (against the current
	// subject) does not authoritatively cover the picked subject's scope
	// set, so do NOT pre-mark consent as already run. Consent re-evaluates
	// after the chooser binds the picked subject.
	//
	// Otherwise the pre-marking uses the same coverage predicate the
	// dispatcher used to decide it needed an interaction at all, so a
	// request routed here *because* consent is owed always reaches the
	// consent screen.
	if !willRunChooser && consentAlreadyCovered(req, existing) {
		interactionsRun[consent.Name] = true
	}
	return interactionsRun
}

func activeChooserGroupID(active *sessions.Active, willRunChooser bool) string {
	if willRunChooser && active.Session != nil {
		return active.Session.ChooserGroupID
	}
	return ""
}

func chooserAddAccountRequested(req *authorize.Request, active *sessions.Active) bool {
	return req.InternalAddAccount && active != nil && active.Session != nil &&
		active.Session.ChooserGroupID != "" &&
		active.Session.ChooserGroupID == req.InternalChooserGroupID
}

func chooserAddAccountGroupID(req *authorize.Request, active *sessions.Active) string {
	if chooserAddAccountRequested(req, active) {
		return active.Session.ChooserGroupID
	}
	return ""
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
// proxy closes the fingerprinting gap (without the
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
	hint authorizeHint,
) {
	if active == nil || (hint.grant == nil && hint.autoGrant == nil) {
		// Defensive: the dispatcher only reaches mintAndRedirect when
		// both are non-nil. Surface a server_error redirect so a
		// future regression is observable.
		emitAuthorizeError(w, r, deps, req, errServerError, "missing session or grant for silent mint")
		return
	}
	codeID, err := newRandomB64(codeByteLength)
	if err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not allocate code")
		return
	}
	durableGrant, parFailure, err := commitSilentAuthorization(
		r.Context(),
		deps,
		req,
		client,
		active,
		hint,
		codeID,
	)
	if err != nil && parFailure {
		emitAuthorizeError(w, r, deps, req, errAccessDenied, "request_uri is no longer valid")
		return
	}
	if err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "could not commit authorization code")
		return
	}
	if hint.autoGrant != nil {
		deps.auditEmitter().Emit(r.Context(), audit.Event{
			Name:      opAuditConsentGrantedFirstParty,
			Level:     audit.LevelInfo,
			Message:   "first-party consent auto-granted",
			ActorID:   active.Session.Subject,
			ClientID:  client.ID,
			SessionID: active.Session.ID,
			IP:        clientIPFromRequest(r, deps).String(),
			UserAgent: truncateUserAgent(r.UserAgent()),
			Extras: map[string]any{
				"grant_id": durableGrant.ID,
				"scope":    append([]string(nil), req.Scope...),
			},
		})
	}
	deps.auditEmitter().Emit(r.Context(), audit.Event{
		Name:      opAuditCodeIssued,
		Level:     audit.LevelInfo,
		Message:   "authorization code issued",
		ActorID:   active.Session.Subject,
		ClientID:  client.ID,
		SessionID: active.Session.ID,
		Extras: map[string]any{
			"code_id":  codeID,
			"grant_id": durableGrant.ID,
			"scope":    append([]string(nil), req.Scope...),
		},
	})
	emitAuthorizeSuccess(w, r, deps, req, codeID)
}

func commitSilentAuthorization(
	ctx context.Context,
	deps resolved,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
	hint authorizeHint,
	codeID string,
) (*store.Grant, bool, error) {
	if deps.Transactions == nil {
		return nil, false, errors.New("authorizeendpoint: transactional store unavailable")
	}
	tx, err := deps.Transactions.BeginTx(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("authorizeendpoint: begin silent transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	txDeps := deps
	txDeps.PARs = tx.PushedAuthRequests()
	txDeps.Codes = tx.AuthorizationCodes()
	txDeps.Grants = tx.Grants()
	durableGrant, err := resolveSilentGrant(ctx, txDeps, req, client, active, hint)
	if err != nil {
		return nil, false, err
	}
	now := deps.now().UTC()
	code := &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             durableGrant.Subject,
		GrantID:             durableGrant.ID,
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
	if err := consumePARIfNeeded(ctx, txDeps, req); err != nil {
		return nil, true, err
	}
	if err := txDeps.Codes.Save(ctx, code); err != nil {
		return nil, false, fmt.Errorf("authorizeendpoint: save silent code: %w", err)
	}
	if err := tx.Commit(); err != nil {
		// A database may durably commit and then lose the ACK. Release the
		// transaction handle before probing the outer store.
		_ = tx.Rollback()
		committedCode, findErr := deps.Codes.Find(ctx, codeID)
		if findErr != nil || !silentAuthorizationCodeMatches(committedCode, code) {
			return nil, false, fmt.Errorf("authorizeendpoint: commit silent transaction: %w", err)
		}
	}
	return durableGrant, false, nil
}

func resolveSilentGrant(
	ctx context.Context,
	deps resolved,
	req *authorize.Request,
	client *store.Client,
	active *sessions.Active,
	hint authorizeHint,
) (*store.Grant, error) {
	if hint.autoGrant != nil {
		return upsertGrant(ctx, deps, *hint.autoGrant)
	}
	grant, err := deps.Grants.Find(ctx, hint.grant.ID)
	if err != nil {
		return nil, fmt.Errorf("authorizeendpoint: reload silent grant: %w", err)
	}
	if grant == nil ||
		grant.ID != hint.grant.ID ||
		grant.ClientID != client.ID ||
		grant.Subject != active.Session.Subject ||
		!scopeIsSubset(req.Scope, grant.Scope) {
		return nil, errors.New("authorizeendpoint: authorization grant unavailable")
	}
	// The grant may have been recorded by an older ceremony than the
	// session now serving this request. Re-stamp the session's context so
	// the id_token reports the authentication the decision matrix just
	// validated max_age / acr_values against, instead of a stale (and
	// possibly stronger) one. The interactive and auto-grant paths do the
	// equivalent through upsertGrant.
	if stampGrantAuthContext(grant, sessionAuthContext(active)) {
		grant.UpdatedAt = deps.now().UTC()
		if err := deps.Grants.Save(ctx, grant); err != nil {
			return nil, fmt.Errorf("authorizeendpoint: refresh silent grant auth context: %w", err)
		}
	}
	return grant, nil
}

func silentAuthorizationCodeMatches(actual, expected *store.AuthorizationCode) bool {
	if actual == nil || expected == nil {
		return false
	}
	return actual.ID == expected.ID &&
		actual.ClientID == expected.ClientID &&
		actual.Subject == expected.Subject &&
		actual.GrantID == expected.GrantID &&
		actual.RedirectURI == expected.RedirectURI &&
		slices.Equal(actual.Scope, expected.Scope) &&
		actual.Resource == expected.Resource &&
		actual.CodeChallenge == expected.CodeChallenge &&
		actual.CodeChallengeMethod == expected.CodeChallengeMethod &&
		actual.Nonce == expected.Nonce &&
		actual.State == expected.State &&
		actual.DPoPJKT == expected.DPoPJKT
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
