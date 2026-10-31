package endsession

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/backchannel"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/i18n"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Clock is the structural wall-clock dependency, mirroring the
// interface in the sibling endpoints so a value satisfying [op.Clock]
// flows through without an adapter. Every wall-clock reading the
// handler takes goes through it — the id_token_hint iat-age cap, the
// revocation tombstone timestamps, and the Max-Age of a session cookie
// rebound to a surviving chooser sibling — so a deployment or a test
// pins all of them with one value.
type Clock interface {
	Now() time.Time
}

// Deps bundles the runtime dependencies the handler needs. The HTTP
// layer constructs a [Deps] once at startup and passes it to
// [Handler]; the handler is otherwise self-contained.
type Deps struct {
	// Issuer is the OP issuer URL. Currently informational; logged
	// on diagnostic paths so a multi-tenant deployment can attribute
	// errors to the right OP.
	Issuer string

	// Clients is the read-only client registry. The handler looks
	// up client_id when no id_token_hint is supplied, and validates
	// that post_logout_redirect_uri is in
	// [op/store.Client.PostLogoutRedirectURIs].
	Clients store.ClientStore

	// Sessions is the chooser-group session manager. The handler
	// reads the active session via [sessions.Manager.Resolve] and
	// deletes it via [sessions.Manager.Logout] on the success path.
	Sessions *sessions.Manager

	// Keys is the OP signing keyset. Required so the id_token_hint
	// verifier can locate the public key matching the token's kid.
	Keys *keys.Set

	// Origins is the allowlist the CSRF gate checks the confirmation
	// POST's Origin / Referer against. It is the same list the
	// /interaction endpoint uses, so both HTML-facing gates admit the
	// same set of request shapes.
	//
	// A nil value falls back to an allowlist holding [Deps.Issuer]
	// alone — the interstitial form is served from the issuer origin
	// and posts back to it, so that is the minimum viable list. When
	// the issuer is missing or not a canonicalisable http(s) origin
	// the fallback list is empty and every confirmation POST is
	// rejected; the gate fails closed rather than falling back to a
	// request-derived origin.
	Origins *csrf.Allowlist

	// Clock supplies the current wall-clock reading. A nil Clock
	// falls back to [timex.SystemClock]; see [Deps.Clock]
	// godoc for why the field exists despite the v1.0 verifier not
	// consulting it.
	Clock Clock

	// LocaleResolver selects the locale of the confirmation page and
	// supplies its two strings. It is the same resolver the interaction
	// endpoint stamps onto a prompt, consulted through the same chain
	// (preferred locale for the subject, the request's ui_locales, the
	// locale cookie, Accept-Language, the configured default).
	//
	// A nil resolver renders the built-in English, which keeps direct
	// callers and embedders who skip i18n on the shape they had. Wiring
	// it is what stops a deployment that ships a non-English catalogue
	// from ending an otherwise localized ceremony on an English page.
	LocaleResolver *i18n.Resolver

	// Backchannel is the [backchannel.Coordinator] the handler hands
	// off to after the session is terminated. A nil value disables
	// back-channel fan-out — the embedder either runs without RPs
	// that registered backchannel_logout_uri, or wires the
	// coordinator manually outside the standard mount point.
	Backchannel *backchannel.Coordinator

	// Grants enumerates the active grants tied to the terminating
	// subject. The handler walks the result and asks
	// [Deps.AccessTokens] to revoke each grant's outstanding access
	// tokens so the OP honours the FAPI 2.0 SP §5.3.2.2 / OIDC
	// RP-Initiated Logout 1.0 §5 expectation that "the OP MAY
	// revoke any active access tokens" once the user signs out.
	// A nil value disables the cascade — the embedder either runs
	// without the access-token registry wired, or accepts that
	// access tokens outlive the session until their JWT exp is
	// reached.
	Grants store.GrantStore

	// AccessTokens revokes the per-grant access-token shadow rows.
	// A nil value disables the cascade for the same reasons listed
	// on [Deps.Grants]; both fields propagate together through
	// [op.New].
	AccessTokens store.AccessTokenRegistry

	// RefreshTokens revokes every refresh-token chain belonging to each
	// grant in the terminating subject snapshot. A nil value disables this
	// branch, preserving deployments that do not issue refresh tokens.
	RefreshTokens store.RefreshTokenStore

	// OpaqueAccessTokens cascades the per-grant opaque-format access
	// tokens alongside the JWT cascade. The two cascades run
	// independently because they belong to different substores; failures
	// are returned to the logout path for accurate auditing while
	// remaining non-blocking for the browser response. A nil value
	// disables the opaque cascade — the embedder either has no opaque-AT
	// deployments or has not wired the substore.
	OpaqueAccessTokens store.OpaqueAccessTokenStore

	// AccessTokenTTL is the issuance TTL the OP applied to JWT access
	// tokens; the handler uses it to compute the tombstone's
	// ExpiresAt under [store.RevocationStrategyGrantTombstone] so
	// every AT issued before the tombstone has either expired or
	// been rejected by the time the row is GC'd. A zero value falls
	// back to a conservative 1-hour ceiling (matches the project's
	// default AccessTokenTTL).
	AccessTokenTTL time.Duration

	// GrantRevocations is the [store.GrantRevocationStore] consulted by
	// the grant-tombstone JWT access-token revocation strategy. The
	// /end_session handler writes a per-grant tombstone here for each
	// affected grant so the cascade is one row per grant rather than one
	// row per AT under that grant. A nil value disables the substore and
	// the handler falls back to whichever legacy behaviour
	// [RevocationStrategy] selects.
	GrantRevocations store.GrantRevocationStore

	// RevocationStrategy selects the JWT access-token revocation shape.
	// The zero value is [store.RevocationStrategyGrantTombstone], which
	// is the documented default; the library wires this from
	// [op.WithAccessTokenRevocationStrategy].
	RevocationStrategy store.AccessTokenRevocationStrategy

	// SubjectProjector converts the OP-internal subject recorded on the
	// browser session into the per-client subject that appears in that
	// client's tokens — the identity function for a public client, the
	// pairwise hash for a pairwise one. The handler uses it to decide
	// whether an id_token_hint names the session it is about to
	// terminate; the projection direction matches the one the token
	// endpoint applies when it mints the id_token's "sub".
	//
	// A nil projector means the OP was not configured with a subject
	// generator, so the session subject and the token subject are the
	// same string and are compared directly.
	SubjectProjector func(ctx context.Context, raw string, client *store.Client) (string, error)

	// Audit is the structured audit-event sink. A nil Emitter falls
	// back to [audit.Discard] so the handler can emit session.destroyed
	// unconditionally on successful OP session termination.
	Audit audit.Emitter

	// ConfirmTemplate replaces the built-in confirmation page when
	// non-nil. It is executed with [interaction.LogoutConfirmTemplateData].
	ConfirmTemplate *template.Template

	// SignedOutTemplate replaces the built-in signed-out page when
	// non-nil. It is executed with [interaction.LogoutSignedOutTemplateData].
	SignedOutTemplate *template.Template

	// LogoutCSP is the declared Content-Security-Policy for the two
	// templated pages. It is re-normalized at render time; an empty or
	// rejected value keeps the strict default.
	LogoutCSP string

	// OnOpaqueOrigin, when non-nil, is called after the confirmation
	// POST is rejected and [csrf.IsOpaqueSameOrigin] holds for it.
	OnOpaqueOrigin func()
}

func (d Deps) audit() audit.Emitter {
	if d.Audit == nil {
		return audit.Discard()
	}
	return d.Audit
}

// Handler returns the HTTP handler the OP mounts at its /end_session
// endpoint. The returned handler is safe for concurrent use; deps
// MUST NOT be mutated after the call.
//
// The CSRF origin allowlist is resolved once here so the per-request
// path never rebuilds it; see [Deps.Origins] for the fallback rule.
func Handler(deps Deps) http.Handler {
	deps.Origins = resolveOrigins(deps)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, deps)
	})
}

// resolveOrigins returns the allowlist the CSRF gate runs against: the
// embedder-supplied list when present, otherwise one derived from the
// issuer. A nil return is a usable "deny everything" list —
// [csrf.Allowlist.Contains] reports false on a nil receiver — which is
// the fail-closed outcome for an OP configured without a usable
// issuer.
func resolveOrigins(deps Deps) *csrf.Allowlist {
	if deps.Origins != nil {
		return deps.Origins
	}
	allow, err := csrf.NewAllowlist([]string{deps.Issuer})
	if err != nil {
		return nil
	}
	return allow
}

// flow is the per-request snapshot every step after parsing shares:
// the wire parameters, the verified id_token_hint claims, the resolved
// client, and the session the cookie points at. Assembling it once in
// [serve] keeps the hint from being verified twice and the session
// from being resolved twice, and it lets the CSRF gate reason about
// the same session the termination step will delete.
type flow struct {
	req     request
	hint    hintClaims
	client  *store.Client
	session sessionLookup
}

// serve is the request-scoped entry point. It validates the shape,
// resolves the requesting client, terminates the session, and emits
// the response. Decomposing the body keeps the function under the
// project's gocognit / cyclop caps.
//
// The serve flow forks on whether the request proves an explicit user
// intent to end THIS browser's session:
//
//   - An id_token_hint whose "sub" names the subject the session
//     cookie authenticates carries that proof: the caller holds an
//     OP-signed token for the very session it asks to terminate.
//     Both GET and POST are accepted directly. A request that
//     resolves no session at all is admitted on the same branch —
//     there is nothing to destroy, so the OP just answers with the
//     post-logout redirect.
//   - Anything else — no hint, or a hint issued for a different
//     subject — is indistinguishable from a cross-site CSRF probe
//     (e.g. <img src=...> carrying the attacker's own id_token). The
//     handler emits an interstitial confirmation page on GET and
//     requires a POST carrying a double-submit __Host- CSRF token
//     before the session is terminated. This is OIDC RP-Initiated
//     Logout 1.0 §5's "the OP SHOULD confirm" plus an OWASP-grade
//     CSRF defense.
func serve(w http.ResponseWriter, r *http.Request, deps Deps) {
	values, ok := readValues(w, r)
	if !ok {
		return
	}
	if _, single := httpx.FirstDuplicateParameter(values, endSessionSingleValuedParams); !single {
		writeLogoutError(w, http.StatusBadRequest, descDuplicateParameter)
		return
	}
	f := flow{req: parseRequest(values)}
	if !validateLogoutScope(w, values, f.req.logoutScope) {
		return
	}
	if !validateRequestBounds(w, f.req) {
		return
	}
	if f.hint, ok = verifyHint(r.Context(), w, deps, f.req); !ok {
		return
	}
	if f.client, ok = resolveClient(r.Context(), w, deps, f.req, f.hint); !ok {
		return
	}
	if !validatePostLogout(w, f.client, f.req.postLogout) {
		return
	}
	f.session = readSessionLookup(r, deps)
	if !admitSessionLookup(w, r, deps, f.session) {
		return
	}
	if !enforceCSRFGate(w, r, deps, f) {
		return
	}
	if err := terminateSessionForScope(w, r, deps, f.session, f.req.logoutScope); err != nil {
		// The session rows the request asked to destroy are still live.
		// Telling the browser the sign-out completed — a redirect to the
		// RP or the "you're signed out" page — would leave a previously
		// stolen cookie usable behind a screen that says otherwise. The
		// session cookie is deliberately left in place for the same
		// reason admitSessionLookup leaves it: it is the only handle the
		// browser has for retrying the logout the OP just failed.
		writeLogoutError(w, http.StatusServiceUnavailable, descInternalError)
		return
	}
	emitResponse(w, r, deps, f)
}

// enforceCSRFGate is the CSRF guard for /end_session. The function
// returns true when the caller may proceed to terminateSessionForScope, false
// when the response has already been written (interstitial page on
// GET, error on a forged POST).
//
// The gate is skipped only when [hintAuthorizesSession] reports that
// the request already carries proof of intent for the session at
// hand. Otherwise:
//
//   - GET / HEAD renders the interstitial confirmation page (HTTP 200)
//     and returns false so the caller stops without touching the
//     session.
//   - POST must present the double-submit __Host- CSRF cookie + form
//     field plus provenance headers [csrf.CheckOrigin] admits; any
//     failure produces a 400 error page and returns false. A
//     cross-site POST that carries a foreign subject's id_token_hint
//     therefore fails closed rather than terminating the browser's
//     session.
//
// The admit / reject decision is the one /interaction/{uid} makes for
// the same request shape — both gates run [csrf.CheckOrigin] against
// the same allowlist and compare their double-submit halves with
// [csrf.ConstantTimeEqual]. Only the rendering differs: /end_session
// is a browser-facing HTML surface, so a rejection is the static
// error page under the endpoint's existing 400 contract rather than
// the interaction endpoint's 403 JSON body.
func enforceCSRFGate(w http.ResponseWriter, r *http.Request, deps Deps, f flow) bool {
	if hintAuthorizesSession(r.Context(), deps, f) {
		return true
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		renderLogoutConfirmation(w, r, deps, f)
		return false
	}
	if !validateOriginOrReferer(r, deps.Origins) {
		if deps.OnOpaqueOrigin != nil && csrf.IsOpaqueSameOrigin(r) {
			deps.OnOpaqueOrigin()
		}
		writeLogoutError(w, http.StatusBadRequest, descCSRFRejected)
		return false
	}
	if f.req.scopeFingerprint != f.req.logoutScope {
		writeLogoutError(w, http.StatusBadRequest, descCSRFRejected)
		return false
	}
	if f.session.fingerprint.sessionID != "" && f.req.chooserGroupID != f.session.fingerprint.chooserGroupID {
		writeLogoutError(w, http.StatusBadRequest, descCSRFRejected)
		return false
	}
	if !validateConfirmToken(r) {
		writeLogoutError(w, http.StatusBadRequest, descCSRFRejected)
		return false
	}
	clearConfirmCookie(w)
	return true
}

// hintAuthorizesSession reports whether id_token_hint substitutes for
// the explicit user gesture the interstitial otherwise demands.
//
// A verified hint proves only that the caller once held an OP-signed
// token for the requesting client. It says nothing about WHOSE browser
// is making the request: any account holder at the same OP can embed
// their own id_token in a cross-site <img src=...> and, without the
// subject check below, force every visitor to be logged out and have
// their access tokens revoked. OIDC RP-Initiated Logout 1.0 §2 calls
// for confirmation when the hint does not match the session, so the
// hint short-circuits the gate only when it names the subject the
// session cookie authenticates.
//
// Two admissions remain:
//
//   - The cookie proved there is no session ([sessionAbsent]). There is
//     nothing to terminate, so the request cannot destroy anyone's
//     login state and the OP answers with the post-logout redirect the
//     RP asked for. The admission keys on that proof rather than on an
//     empty fingerprint: a lookup the store could not answer produces
//     the same empty fingerprint and must not buy the same exemption.
//   - Matching subject. The comparison runs in the per-client subject
//     space: the session stores the OP-internal subject while the
//     id_token carries whatever [Deps.SubjectProjector] derived for
//     the resolved client (identity for a public client, the pairwise
//     hash for a pairwise one).
//
// A hint without "sub", or a projection that fails, counts as "does
// not match" so every unexpected shape falls back to the confirmation
// page instead of skipping the gate.
func hintAuthorizesSession(ctx context.Context, deps Deps, f flow) bool {
	if f.req.idTokenHint == "" {
		return false
	}
	if f.session.state == sessionAbsent {
		return true
	}
	sess := f.session.fingerprint
	if f.hint.subject == "" || sess.subject == "" {
		return false
	}
	projected, ok := projectSessionSubject(ctx, deps, sess.subject, f.client)
	return ok && projected == f.hint.subject
}

// projectSessionSubject maps the OP-internal session subject onto the
// subject space of client. A nil [Deps.SubjectProjector] means the OP
// runs without a subject generator, so the two spaces coincide. The
// bool reports whether a usable value was produced; a projector error
// or an empty result yields false, which the caller reads as "cannot
// prove a match".
func projectSessionSubject(
	ctx context.Context,
	deps Deps,
	raw string,
	client *store.Client,
) (string, bool) {
	if deps.SubjectProjector == nil {
		return raw, true
	}
	projected, err := deps.SubjectProjector(ctx, raw, client)
	if err != nil || projected == "" {
		return "", false
	}
	return projected, true
}

// verifyHint validates id_token_hint when the request carries one and
// returns the claims the rest of the flow acts on. A hint-less request
// yields the zero value and true; an unverifiable hint writes the 400
// page and returns false.
//
// The verifier consults [Deps.Clock] (or [timex.SystemClock] as a
// fallback) so the iat-age cap inside [verifyIDTokenHint] is testable
// against a fixed clock and consistent with the rest of the handler's
// time references.
func verifyHint(ctx context.Context, w http.ResponseWriter, deps Deps, req request) (hintClaims, bool) {
	if req.idTokenHint == "" {
		return hintClaims{}, true
	}
	claims, err := verifyIDTokenHint(ctx, deps.Keys, deps.Issuer, req.idTokenHint, hintNow(deps.Clock))
	if err != nil {
		writeLogoutError(w, http.StatusBadRequest, descIDTokenInvalid)
		return hintClaims{}, false
	}
	return claims, true
}

// resolveClient identifies the requesting client from the verified
// id_token_hint claims and / or the client_id parameter. The function
// returns nil when no client can be identified and that absence is
// acceptable (no hint and no post_logout_redirect_uri); otherwise it
// writes the error response and returns false.
//
// Resolution order:
//
//  1. id_token_hint present: use the client the verified claims name.
//     If client_id is also present and differs, fail.
//  2. Only client_id present: look it up.
//  3. Neither present: succeed with a nil client.
func resolveClient(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	req request,
	hint hintClaims,
) (*store.Client, bool) {
	switch {
	case req.idTokenHint != "":
		if req.clientID != "" && req.clientID != hint.clientID {
			writeLogoutError(w, http.StatusBadRequest, descClientIDDisagrees)
			return nil, false
		}
		return resolveByClientID(ctx, w, deps, hint.clientID)
	case req.clientID != "":
		return resolveByClientID(ctx, w, deps, req.clientID)
	default:
		return nil, true
	}
}

// resolveByClientID looks id up in the client registry. Both
// "client unknown" and "store transport fault" surface as the same
// descClientNotFound description so the wire response is not an
// existence oracle for client identifiers; the underlying error is
// preserved in logs (when wired) for operator diagnostics.
func resolveByClientID(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	id string,
) (*store.Client, bool) {
	c, err := deps.Clients.GetClient(ctx, id)
	if err != nil {
		// Both [store.ErrNotFound] and any transport fault surface
		// identically on the wire so the response is not an existence
		// oracle for client identifiers. The audit stream is not the
		// wire and does carry the difference: a client that does not
		// exist and a registry that stopped answering call for opposite
		// operator responses, and "unknown client" on every request is
		// what a failing registry looks like from the outside.
		//
		// A clean miss emits nothing. Every mistyped client_id would
		// otherwise raise an event and bury the one that matters.
		if !errors.Is(err, store.ErrNotFound) {
			deps.audit().Emit(ctx, audit.Event{
				Name:     string(auditevent.AuditLogoutClientLookupFailed),
				Level:    audit.LevelError,
				Message:  "client registry lookup failed; the request is refused but the client was not judged",
				ClientID: id,
				Extras:   map[string]any{"reason": "store_unavailable"},
			})
		}
		writeLogoutError(w, http.StatusBadRequest, descClientNotFound)
		return nil, false
	}
	return c, true
}

// validatePostLogout enforces the rule that post_logout_redirect_uri
// requires a resolved client and a matching entry in
// [op/store.Client.PostLogoutRedirectURIs]: exact, or the RFC 8252 §7.3
// loopback any-port match a native or public client is allowed. An
// empty value is always valid; the handler renders the static
// confirmation page in that case.
func validatePostLogout(w http.ResponseWriter, client *store.Client, postLogout string) bool {
	if postLogout == "" {
		return true
	}
	if client == nil {
		writeLogoutError(w, http.StatusBadRequest, descPostLogoutRequiresClient)
		return false
	}
	for _, uri := range client.PostLogoutRedirectURIs {
		// Honour the same RFC 8252 §7.3 loopback any-port allowance as the
		// /authorize redirect_uri check: a native client registers a fixed
		// loopback URI but binds an ephemeral port at logout time, so an
		// exact-match-only gate here would reject a callback /authorize
		// would have accepted.
		if authorize.LoopbackURIMatches(client, uri, postLogout) {
			return true
		}
	}
	writeLogoutError(w, http.StatusBadRequest, descPostLogoutNotRegistered)
	return false
}

// emitResponse writes the success response: a 302 to the post-logout
// URI when one is supplied, or the static confirmation page
// otherwise. The redirect URI has already been validated against the
// resolved client; state is echoed verbatim per OIDC RP-Initiated
// Logout 1.0 §3.
//
// On a malformed post_logout_redirect_uri (which validatePostLogout
// has already accepted as preregistered, so a parse failure here is a
// programmer bug or a corrupted client record) the function falls
// through to the static confirmation page rather than emitting the
// raw value as a Location header. Surfacing the malformed string as a
// redirect target risks an open-redirect surface against any future
// regression that loosens validatePostLogout's exact-match rule.
func emitResponse(w http.ResponseWriter, r *http.Request, deps Deps, f flow) {
	if f.req.postLogout == "" {
		writeLoggedOutPage(w, deps, resolveLoggedOutPage(r, deps, f))
		return
	}
	target, ok := buildPostLogoutRedirect(f.req.postLogout, f.req.state)
	if !ok {
		writeLoggedOutPage(w, deps, resolveLoggedOutPage(r, deps, f))
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// resolveLoggedOutPage selects the confirmation page's locale and looks
// up its two strings.
//
// The subject comes from the session the request arrived with, so a
// signed-in user's stored locale preference wins here exactly as it
// does on the login and consent screens. It is read before the session
// is destroyed, which is why the flow — not just the request — is
// threaded down to this point.
//
// A nil resolver returns the zero page, which renders the built-in
// English.
func resolveLoggedOutPage(r *http.Request, deps Deps, f flow) loggedOutPage {
	if deps.LocaleResolver == nil {
		return loggedOutPage{}
	}
	tag := deps.LocaleResolver.Resolve(r.Context(), localeRequest(r, f))
	page := loggedOutPage{locale: string(tag)}
	if title, ok := deps.LocaleResolver.Message(tag, loggedOutTitleKey, nil); ok {
		page.title = title
	}
	if body, ok := deps.LocaleResolver.Message(tag, loggedOutBodyKey, nil); ok {
		page.body = body
	}
	return page
}

// localeRequest assembles the resolver input both /end_session pages
// share. Keeping it in one place is what stops the confirmation page
// and the logged-out page from answering a user's language preference
// differently within the same ceremony.
//
// The subject comes from the session the request arrived with, and the
// caller reads it before the session is destroyed, so a signed-in
// user's stored preference wins here exactly as it does on the login
// and consent screens.
func localeRequest(r *http.Request, f flow) i18n.Request {
	cookieVal := ""
	if c, err := r.Cookie(cookie.LocaleProfile.Name); err == nil {
		cookieVal = c.Value
	}
	return i18n.Request{
		Subject:        f.session.fingerprint.subject,
		UILocales:      strings.Fields(f.req.uiLocales),
		Cookie:         cookieVal,
		AcceptLanguage: r.Header.Get("Accept-Language"),
	}
}

// buildPostLogoutRedirect composes the post-logout redirect target.
// The function is split out so the query-merge logic can be unit-
// tested without invoking the HTTP machinery. The bool reports whether
// the URI parsed successfully; a parse failure short-circuits the
// caller onto the static confirmation page rather than emitting the
// raw (potentially attacker-shaped) value as a Location header.
func buildPostLogoutRedirect(postLogout, state string) (string, bool) {
	u, err := url.Parse(postLogout)
	if err != nil {
		return "", false
	}
	if state == "" {
		return postLogout, true
	}
	q := u.Query()
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String(), true
}
