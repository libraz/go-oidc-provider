package authorizeendpoint

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/store"
)

// opAuditConsentGrantedFirstParty mirrors the public
// op.AuditConsentGrantedFirstParty constant. The internal package
// cannot import op (one-way import graph), so the value is duplicated
// here and pinned by TestAuditEvent_FirstPartyMirror in
// op/audit_test.go.
const opAuditConsentGrantedFirstParty = string(auditevent.AuditConsentGrantedFirstParty)

const (
	opAuditCodeIssued              = string(auditevent.AuditCodeIssued)
	opAuditConsentGranted          = string(auditevent.AuditConsentGranted)
	opAuditSessionCreated          = string(auditevent.AuditSessionCreated)
	opAuditInteractionRenderFailed = string(auditevent.AuditInteractionRenderFailed)
	opAuditRedirectURIMismatch     = string(auditevent.AuditRedirectURIMismatch)
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
		if !endpointsupport.IsFormContent(r.Header.Get("Content-Type")) {
			renderBrowserError(w, r, deps.Driver, http.StatusBadRequest, errInvalidRequest,
				"content-type must be application/x-www-form-urlencoded", "")
			return
		}
		endpointsupport.LimitFormBody(w, r)
	} else if len(r.URL.RawQuery) > endpointsupport.MaxFormBytes {
		// The query is persisted into the interaction record, so GET is
		// held to the same ceiling as a POST body.
		renderBrowserError(w, r, deps.Driver, http.StatusRequestURITooLong, errInvalidRequest,
			"request query is too large", "")
		return
	}
	values, err := authorize.ExtractValues(r)
	if err != nil {
		writeAuthorizeParseError(w, r, deps, err)
		return
	}
	req, ok := resolveAuthorizeRequest(w, r, deps, values)
	if !ok {
		return
	}
	client, err := requireFound(deps.Clients.GetClient(r.Context(), req.ClientID))
	if err != nil {
		renderClientLookupError(w, r, deps, err, req.State)
		return
	}
	if err := req.ValidateEffectiveRequest(client, deps.Scopes, deps.RequestPolicy, deps.ACRValuesSupported); err != nil {
		writeAuthorizeValidationError(w, r, req, client, deps, err)
		return
	}
	if !validateRequestExtensions(w, r, deps, req, client) {
		return
	}
	dispatchAuthorize(w, r, deps, req, client)
}

// validateRequestExtensions runs the request gates that sit between a
// successful [authorize.Request.Validate] and dispatch: the JARM
// response_mode rules, RFC 9396 authorization_details, the Grant
// Management draft parameters, and the RFC 9449 §10.1 "dpop_jkt"
// commitment.
//
// The rules live in [authorize.Request.ValidateExtensions] and the
// policy in [Deps.ExtensionPolicy], both shared with the
// pushed-authorization-request endpoint so the two consecutive gates on
// the same request cannot disagree about either. This
// function only renders: the checks run after [authorize.Request.Validate]
// so redirect_uri has been matched against the client's registration and
// the rejection can take the endpoint's normal channel (JARM / form_post
// / redirect) rather than a pre-redirect first-party page. A rejection of
// the JARM response_mode itself leaves that channel through
// [emitAuthorizeError]'s plain-response fallback: JARM cannot be used to
// convey "JARM is not in use here".
//
// Returns false when it wrote the response; the caller then stops.
func validateRequestExtensions(
	w http.ResponseWriter,
	r *http.Request,
	deps resolved,
	req *authorize.Request,
	client *store.Client,
) bool {
	rejection := req.ValidateExtensions(r.Context(), client, deps.ExtensionPolicy)
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

// resolveAuthorizeRequest is the parse + PAR / JAR-consumption gate.
// The order is:
//  1. PAR: a "request_uri" matching the urn:ietf:params:oauth:request_uri:
//     prefix is consumed from the persisted record (RFC 9126 §2.3) and
//     every other parameter except client_id is ignored.
//  2. JAR: a "request" parameter — or a "request_uri" outside the PAR
//     URN namespace — is resolved by [resolveJARRequestIfNeeded] and
//     merged onto the wire values per RFC 9101 §6.1; the merged values
//     are then re-parsed. The non-URN form is the RFC 9101 §5.2.2
//     by-reference surface, and the OP does fetch it: see
//     [fetchJARRequestURI] for the outbound posture it runs under —
//     the URI MUST appear verbatim in the client's preregistered
//     [op/store.Client.RequestURIs], and the retrieval goes through the
//     shared SSRF-gated envelope (https-only unless
//     [op.WithAllowPrivateNetwork] ([op.OutboundJAR]) is set, cloud-metadata always
//     blocked, no redirects, JWS media types only, capped body).
//     [authorize.ParseValues]'s [authorize.ErrInvalidRequestURI] branch
//     is the parser-side backstop behind that gate: by the time it runs,
//     a JAR request_uri has already been consumed and stripped from the
//     values, so anything left that is not a PAR URN is malformed.
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
	// The wire-level rejection of a malformed payload fires above, so a
	// hostile RP cannot probe the OP through claims-shaped junk.
	req.DropClaimsUnless(deps.ClaimsParameterEnabled)
	return req, true
}

// methodAllowed reports whether the HTTP method is one of GET / POST. The
// authorize endpoint accepts both per RFC 6749 §3.1.
func methodAllowed(method string) bool {
	return method == http.MethodGet || method == http.MethodPost
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
func writeAuthorizeValidationError(w http.ResponseWriter, r *http.Request, req *authorize.Request, client *store.Client, deps resolved, err error) {
	var ae *authorize.Error
	if !errors.As(err, &ae) {
		logServerError(r, deps, "", err)
		renderBrowserError(w, r, deps.Driver, http.StatusInternalServerError, errServerError, "", req.State)
		return
	}
	if errors.Is(err, authorize.ErrPKCERequired) && client != nil && !authorize.ClientRequiresPKCE(client) {
		logPKCERequiredHint(r.Context(), deps, client.ID)
	}
	if errors.Is(err, authorize.ErrRedirectURIInvalid) {
		deps.auditEmitter().Emit(r.Context(), audit.Event{
			Name:     opAuditRedirectURIMismatch,
			Level:    audit.LevelWarn,
			Message:  "redirect_uri is not registered for this client",
			ClientID: req.ClientID,
			Extras: map[string]any{
				"endpoint":     "authorize",
				"redirect_uri": req.RedirectURI,
			},
		})
	}
	if !authorize.IsRedirectSafe(err) {
		renderBrowserError(w, r, deps.Driver, http.StatusBadRequest, ae.Code, ae.Description, req.State)
		return
	}
	emitAuthorizeError(w, r, deps, req, ae.Code, ae.Description)
}

// logPKCERequiredHint warns, once per client_id per handler, that a
// confidential client was refused only because the active profile makes
// PKCE mandatory. A nil Logger discards.
func logPKCERequiredHint(ctx context.Context, deps resolved, clientID string) {
	if deps.Logger == nil {
		return
	}
	if _, seen := deps.pkceHintLogged.LoadOrStore(clientID, struct{}{}); seen {
		return
	}
	deps.Logger.LogAttrs(ctx, slog.LevelWarn, "authorization request refused: code_challenge is required",
		slog.String("client_id", clientID),
		slog.String("hint", "the active profile requires PKCE for every client; op.WithProfile(profile.OIDCCore) makes it optional for confidential clients"))
}

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
	active, sessErr := resolveSession(w, r, deps)
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
		cookie.ClearOn(w, cookie.SessionProfile)
	}
	hint, err := computeAuthorizeHint(r.Context(), deps, req, client, active, now)
	if err != nil {
		emitAuthorizeError(w, r, deps, req, errServerError, "grant backend unavailable")
		return
	}
	hint = applyExitOverrides(r, deps, req, client, active, hint)
	switch hint.decision {
	case decisionLoginRequired:
		emitAuthorizeError(w, r, deps, req, errLoginRequired, "user authentication is required")
	case decisionConsentRequired:
		emitAuthorizeError(w, r, deps, req, errConsentRequired, "user consent is required")
	case decisionInteractionRequired:
		emitAuthorizeError(w, r, deps, req, errInteractionRequired, "interaction is required")
	case decisionInteract:
		startInteraction(w, r, deps, req, client, active, hint)
	case decisionMint:
		mintAndRedirect(w, r, deps, req, client, active, hint)
	}
}

// renderClientLookupError answers a failed client lookup. redirect_uri
// is not yet trusted, so the response stays pre-redirect (HTML for a
// browser, JSON for an API caller). Only an unknown client is
// invalid_request; a backend that could not answer is server_error, so
// an outage is not reported as an unregistered client_id.
func renderClientLookupError(w http.ResponseWriter, r *http.Request, deps resolved, err error, state string) {
	if errors.Is(err, store.ErrNotFound) {
		renderBrowserError(w, r, deps.Driver, http.StatusBadRequest, errInvalidRequest, "client_id is not registered", state)
		return
	}
	renderServerError(w, r, deps, "client backend unavailable", err)
}
