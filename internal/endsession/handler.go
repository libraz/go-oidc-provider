package endsession

import (
	"context"
	"errors"
	"fmt"
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
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/i18n"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// endSessionSingleValuedParams enumerates the request parameters
// OIDC RP-Initiated Logout 1.0 §2 lists with single-valued
// semantics, plus the confirmation-token field the hint-less POST
// branch reads from the double-submit cookie. RFC 6749 §3.2 forbids
// duplicates for these names; the /end_session endpoint joins the
// same input-shape policy as the token / PAR / CIBA surfaces by
// rejecting any repeat at the dispatcher level.
//
//nolint:gochecknoglobals // closed enumeration; declared once and treated as a constant lookup table.
var endSessionSingleValuedParams = []string{
	"id_token_hint",
	"client_id",
	"post_logout_redirect_uri",
	"state",
	"logout_hint",
	"ui_locales",
	"logout_scope",
	"logout_scope_fingerprint",
	"chooser_group_id",
	confirmTokenField,
}

const (
	logoutScopeAll     = "all"
	logoutScopeCurrent = "current"
)

// maxQueryBytes caps the byte-length of [http.Request.URL.RawQuery] on
// the GET branch of /end_session. RFC 9700 §2.4 recommends keeping
// query strings short to reduce log-leak amplification; 8 KiB is well
// above any legitimate payload (id_token_hint + post_logout_redirect_uri
// + state + client_id) and well below the practical browser / proxy
// query-length limits, so a hostile request that slips a multi-KiB
// state value through is rejected before any further processing.
const maxQueryBytes = 8 * 1024

// maxStateBytes caps the byte-length of the "state" query parameter
// the OP echoes back on the post-logout redirect. OIDC RP-Initiated
// Logout 1.0 §3 does not bound the value, but real RPs use 128 - 512
// byte opaque tokens; 2 KiB is comfortably above that while bounding
// the server-side reflection surface against a hostile RP that crafts
// an oversized state to amplify response size or leak data through
// the redirect target.
const maxStateBytes = 2 * 1024

// maxIDTokenHintAge caps how old an id_token_hint may be measured by
// its "iat" claim against the current wall clock. RFC 9700 §2.4
// recommends bounding the freshness of even non-cryptographically-
// authenticated hints; 30 days is well above the OP's usual id_token
// lifetime (an hour) while still rejecting the long-tail of stale
// tokens that an attacker could harvest from forgotten browser tabs
// or proxy logs. The check applies only when "iat" is present; the
// signature / issuer / aud validation continues to gate everything
// else.
const maxIDTokenHintAge = 30 * 24 * time.Hour

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

// request carries the parsed parameters the handler operates on. The
// fields mirror the OIDC RP-Initiated Logout 1.0 §2 wire shape minus
// the parameters the handler ignores entirely (logout_hint — see the
// package godoc for why). Adding an ignored field back is purely
// additive when the library grows a chooser UX surface.
type request struct {
	idTokenHint      string
	clientID         string
	postLogout       string
	state            string
	logoutScope      string
	scopeFingerprint string
	chooserGroupID   string
	// uiLocales is the space-delimited OIDC RP-Initiated Logout §2
	// "ui_locales" preference. It feeds the confirmation page's locale
	// resolution and is read nowhere else.
	uiLocales string
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

// sessionFingerprint is the pair the handler reads out of the session
// cookie: the session id to delete and the OP-internal subject whose
// grants the logout cascade retires.
type sessionFingerprint struct {
	sessionID      string
	subject        string
	chooserGroupID string
}

// sessionState classifies what reading the session cookie proved. The
// three values are the only outcomes the logout flow may act on, and
// keeping them apart is a security property rather than a nicety: a
// backend that could not answer says nothing about whether a session
// exists, so folding it onto "there is nothing here" would let a
// storage outage produce a logout that destroys nothing while the
// response, the audit stream and the logout-failure counter all report
// a completed sign-out.
type sessionState uint8

const (
	// sessionStoreUnavailable is the zero value on purpose. A lookup
	// that no branch classified must read as "the store did not answer",
	// because that is the outcome whose mishandling is unsafe; a value
	// nobody set can then never be mistaken for a resolved absence.
	sessionStoreUnavailable sessionState = iota

	// sessionAbsent means the cookie proved there is nothing to
	// terminate: it was missing, it did not decrypt, or it named a
	// session the store has confirmed is gone or expired.
	sessionAbsent

	// sessionActive means the cookie resolved to a live session whose
	// fingerprint is carried alongside.
	sessionActive
)

// sessionLookup is the three-valued result of reading the session
// cookie. The fingerprint travels with its state so every consumer
// decides from the classification rather than from whether the
// fingerprint happens to be empty — the distinction between "resolved
// absent" and "unresolvable" is invisible in the fingerprint alone.
type sessionLookup struct {
	state       sessionState
	fingerprint sessionFingerprint
	// err carries the backend failure behind [sessionStoreUnavailable]
	// so the audit record names the cause. It is nil in every other
	// state.
	err error
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

// admitSessionLookup decides whether the flow may continue past the
// session read. It returns true for the two states that describe the
// session — resolved, or proven absent — and false once it has written
// the response for a session store that could not answer.
//
// The unavailable branch deliberately does all three of the following,
// because dropping any one of them turns an outage into a silent
// no-op:
//
//   - Emits [auditevent.AuditSessionDestroyFailed] (which the metrics
//     bridge projects onto the logout-failure counter), so the outage is
//     visible on the same stream a real deletion failure appears on.
//   - Stops before the CSRF gate. The gate's "nothing to terminate"
//     admission is only sound when the OP knows there is nothing to
//     terminate; an unanswered lookup is not that knowledge, and
//     admitting on it would let a cross-site request skip the
//     confirmation whenever the backend is down.
//   - Stops before the response. The browser must not be told the
//     sign-out completed while the session row and the subject's tokens
//     are still live.
//
// The session cookie is left in place. Clearing it is permitted on
// every path, but here it would cost the only handle the browser has on
// the session that is still running: the user could no longer retry the
// logout the OP just failed to perform.
//
// The switch has no default clause so the exhaustiveness check binds; a
// state added later must state its own policy rather than inheriting a
// permissive one, and the fallthrough return is a refusal either way.
func admitSessionLookup(w http.ResponseWriter, r *http.Request, deps Deps, lookup sessionLookup) bool {
	switch lookup.state {
	case sessionActive, sessionAbsent:
		return true
	case sessionStoreUnavailable:
		emitSessionLookupFailed(r.Context(), deps, lookup)
		writeLogoutError(w, http.StatusServiceUnavailable, descInternalError)
		return false
	}
	return false
}

// emitSessionLookupFailed records that the OP could not read the
// session it was asked to terminate. The event is the same one a failed
// deletion emits: from the outside both mean "a session may still be
// live after a logout request", and an operator watching the
// logout-failure counter needs the read failures in it as much as the
// write failures.
func emitSessionLookupFailed(ctx context.Context, deps Deps, lookup sessionLookup) {
	extras := map[string]any{}
	if lookup.err != nil {
		extras["error"] = lookup.err.Error()
	}
	deps.audit().Emit(ctx, audit.Event{
		Name:    string(auditevent.AuditSessionDestroyFailed),
		Level:   audit.LevelError,
		Message: "session lookup failed; nothing was terminated",
		Extras:  extras,
	})
}

// validateRequestBounds enforces the per-parameter size caps the
// /end_session endpoint applies to mitigate amplification / log-leak
// attacks against the post-logout redirect target. The bounds:
//
//   - state at [maxStateBytes] (2 KiB). The value is echoed back on
//     the post-logout redirect; an unbounded state amplifies the
//     attacker-controllable payload that lands in proxy logs and
//     browser history.
//
// Other parameters (id_token_hint, post_logout_redirect_uri,
// client_id) inherit the [maxQueryBytes] / [endpointsupport.MaxFormBytes]
// gate readValues installed; the per-field cap here applies to the one
// value that flows back to the user agent.
func validateRequestBounds(w http.ResponseWriter, req request) bool {
	if len(req.state) > maxStateBytes {
		writeLogoutError(w, http.StatusRequestURITooLong, descRequestTooLarge)
		return false
	}
	return true
}

// enforceCSRFGate is the CSRF guard for /end_session. The function
// returns true when the caller may proceed to terminateSession, false
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

// readValues enforces the method / content-type / size invariants and
// returns the parsed parameter map. The bool reports whether the
// caller should continue: false means a response was already written.
//
// On the GET branch the function caps [http.Request.URL.RawQuery] at
// [maxQueryBytes]: a hostile RP that crafts a multi-megabyte query
// string would otherwise force the OP to allocate megabytes of
// url-decoded form state before the per-field validation runs. The
// 8 KiB cap is well above the documented sum of legitimate parameters
// (id_token_hint + post_logout_redirect_uri + state + client_id) and
// well below the practical browser / proxy query-length limits.
func readValues(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodHead+", "+http.MethodPost)
		writeLogoutError(w, http.StatusMethodNotAllowed, descMethodNotAllowed)
		return nil, false
	}
	if r.Method == http.MethodPost {
		if !isFormContent(r.Header.Get("Content-Type")) {
			writeLogoutError(w, http.StatusBadRequest, descContentTypeRequired)
			return nil, false
		}
		endpointsupport.LimitFormBody(w, r)
		if err := r.ParseForm(); err != nil {
			writeLogoutError(w, http.StatusBadRequest, descMalformedForm)
			return nil, false
		}
		return r.PostForm, true
	}
	if r.URL != nil && len(r.URL.RawQuery) > maxQueryBytes {
		writeLogoutError(w, http.StatusRequestURITooLong, descRequestTooLarge)
		return nil, false
	}
	return r.URL.Query(), true
}

// parseRequest projects the raw parameter map onto the typed
// [request]. "ui_locales" is extracted because the confirmation page
// resolves its strings and the parameter is that chain's second link;
// the value reaches [i18n.Resolver.Resolve] and nothing else, so it is
// never logged or echoed. "logout_hint" is still intentionally not
// extracted: no surface consumes it, and storing the value would only
// invite a future regression that surfaces it through a log line or
// audit record without sanitisation.
func parseRequest(v url.Values) request {
	scope := logoutScopeAll
	if raw, ok := v["logout_scope"]; ok && len(raw) == 1 {
		scope = raw[0]
	}
	return request{
		idTokenHint:      v.Get("id_token_hint"),
		clientID:         v.Get("client_id"),
		postLogout:       v.Get("post_logout_redirect_uri"),
		state:            v.Get("state"),
		logoutScope:      scope,
		scopeFingerprint: v.Get("logout_scope_fingerprint"),
		chooserGroupID:   v.Get("chooser_group_id"),
		uiLocales:        v.Get("ui_locales"),
	}
}

func validateLogoutScope(w http.ResponseWriter, values url.Values, scope string) bool {
	if _, present := values["logout_scope"]; !present {
		return true
	}
	if scope == logoutScopeCurrent {
		return true
	}
	writeLogoutError(w, http.StatusBadRequest, descInvalidLogoutScope)
	return false
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
		// oracle for client identifiers; the underlying error is
		// preserved in logs (when wired) for operator diagnostics.
		writeLogoutError(w, http.StatusBadRequest, descClientNotFound)
		return nil, false
	}
	return c, true
}

// validatePostLogout enforces the rule that post_logout_redirect_uri
// requires a resolved client and an exact-match entry in
// [op/store.Client.PostLogoutRedirectURIs]. An empty value is always
// valid; the handler renders the static confirmation page in that
// case.
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

// terminateSession is the success-path side effect: delete the session
// record the cookie pointed at, hand a back-channel logout fan-out to
// the affected RPs off to the coordinator, and clear the cookie in the
// response. Downstream revocation and back-channel failures are
// deliberately non-blocking for the browser response, but they are
// recorded as distinct audit events rather than being misreported as a
// successful session destruction. A failure to delete the session rows
// themselves is returned to the caller: the browser must not be told the
// sign-out completed while the session it names is still usable.
//
// The ordering here is load-bearing. Session deletion and the
// access-token cascade run on the request path, so the response is
// never written while the session the user asked to end is still live.
// Back-channel delivery does not: it is an out-of-band exchange with
// the relying parties, bounded only by how fast the slowest of them
// answers, so it is detached and the caller proceeds to write the
// response.
//
// lookup is the classified session read [serve] performed before the
// CSRF gate ran, so the session that gets destroyed is exactly the one
// the gate authorised.
func terminateSession(w http.ResponseWriter, r *http.Request, deps Deps, lookup sessionLookup) error {
	return terminateSessionForScope(w, r, deps, lookup, logoutScopeAll)
}

// terminateSessionForScope performs the destructive part of /end_session.
// The all-scope branch snapshots the chooser group before deleting anything;
// the snapshot is the source of truth for both the revocation and BCL
// cascades. The current-scope branch removes only the active row and lets the
// session manager rebind the cookie to a surviving sibling.
//
// It returns a non-nil error when the OP could not confirm that every
// session row in the requested scope is gone. On that path the session
// cookie is left untouched, so the browser keeps the one handle it has
// for retrying, and the caller MUST NOT report success.
//
// The state switch is a backstop rather than the primary gate — [serve]
// answers an unavailable store before the flow reaches here — but it is
// what makes the destructive path safe for any future caller: it cannot
// be handed a lookup that never resolved a session and treat the
// resulting empty fingerprint as an idempotent no-op.
//
//nolint:gocognit,cyclop // The destructive workflow keeps failure audit, revocation, and cookie ordering explicit.
func terminateSessionForScope(w http.ResponseWriter, r *http.Request, deps Deps, lookup sessionLookup, scope string) error {
	ctx := r.Context()
	if scope == "" {
		scope = logoutScopeAll
	}

	switch lookup.state {
	case sessionAbsent:
		clearSessionCookie(w)
		return nil
	case sessionStoreUnavailable:
		// No session was ever resolved, so there is nothing this
		// function could delete. Record the fault instead of returning
		// as though the logout had nothing to do.
		emitSessionLookupFailed(ctx, deps, lookup)
		return errSessionNotDestroyed
	case sessionActive:
		// Fall through to the destructive workflow.
	}

	sess := lookup.fingerprint
	if sess.sessionID == "" {
		clearSessionCookie(w)
		return nil
	}

	snapshot := make([]*store.Session, 0, 1)
	var sessionErr error
	var removal sessions.Removal
	switch scope {
	case logoutScopeCurrent:
		// The session fingerprint was resolved immediately before the CSRF
		// gate. Preserve it even when the row disappears during the gate so
		// token and BCL cascades still describe the operation the user
		// confirmed.
		snapshot = append(snapshot, &store.Session{
			ID:             sess.sessionID,
			Subject:        sess.subject,
			ChooserGroupID: sess.chooserGroupID,
		})
		if sess.chooserGroupID == "" {
			sessionErr = deps.Sessions.Logout(ctx, sess.sessionID)
		} else {
			removal, sessionErr = deps.Sessions.Remove(ctx, sess.chooserGroupID, sess.sessionID, sess.sessionID)
		}
	default:
		if sess.chooserGroupID == "" {
			sessionErr = errors.New("endsession: active session has no chooser group")
		} else {
			var err error
			snapshot, err = deps.Sessions.SnapshotGroup(ctx, sess.chooserGroupID)
			if err != nil {
				sessionErr = err
				// Keep the active row in the cascade and make one best-effort
				// deletion attempt. A failed snapshot cannot safely be claimed
				// as group-wide success, but leaving the active row untouched is
				// worse for the browser that explicitly confirmed logout.
				snapshot = append(snapshot, &store.Session{
					ID:             sess.sessionID,
					Subject:        sess.subject,
					ChooserGroupID: sess.chooserGroupID,
				})
				if logoutErr := deps.Sessions.Logout(ctx, sess.sessionID); logoutErr != nil && !errors.Is(logoutErr, store.ErrNotFound) {
					sessionErr = errors.Join(sessionErr, logoutErr)
				}
			} else {
				sessionErr = deps.Sessions.LogoutAllSnapshot(ctx, snapshot)
			}
		}
	}
	if scope != logoutScopeCurrent && len(snapshot) == 0 && sessionErr == nil {
		// The active cookie was valid when the request entered the flow,
		// but the chooser group was already empty by the time the
		// destructive snapshot ran. Treat this as an idempotent logout
		// outcome and retain the explicit audit distinction from a live
		// row that failed to delete.
		deps.audit().Emit(ctx, audit.Event{
			Name:      string(auditevent.AuditSessionAlreadyAbsent),
			Level:     audit.LevelInfo,
			Message:   "session was already absent",
			ActorID:   sess.subject,
			SessionID: sess.sessionID,
		})
	}

	for _, row := range snapshot {
		if row == nil || row.ID == "" {
			continue
		}
		if sessionErr == nil {
			deps.audit().Emit(ctx, audit.Event{
				Name:      string(auditevent.AuditSessionDestroyed),
				Level:     audit.LevelInfo,
				Message:   "session destroyed",
				ActorID:   row.Subject,
				SessionID: row.ID,
			})
		} else {
			deps.audit().Emit(ctx, audit.Event{
				Name:      string(auditevent.AuditSessionDestroyFailed),
				Level:     audit.LevelError,
				Message:   "session logout persistence failed",
				ActorID:   row.Subject,
				SessionID: row.ID,
				Extras:    map[string]any{"error": sessionErr.Error()},
			})
		}
	}

	if err := revokeAccessTokensForSnapshot(ctx, deps, snapshot); err != nil {
		deps.audit().Emit(ctx, audit.Event{
			Name:    string(auditevent.AuditLogoutTokenRevokeFailed),
			Level:   audit.LevelError,
			Message: "logout token revocation failed",
			Extras:  map[string]any{"error": err.Error()},
		})
	}
	notifyBackchannelForSnapshot(ctx, deps, snapshot)

	if sessionErr != nil {
		// At least one session row survived the request. Leave the cookie
		// alone: it is the browser's only handle on the session that is
		// still running, and clearing it would cost the user the ability
		// to retry the logout the OP just failed to perform.
		return sessionErr
	}
	if scope == logoutScopeCurrent && removal.Cookie != "" && len(removal.Remaining) > 0 {
		if err := setSessionCookie(w, removal.Cookie, removal.ExpiresAt, endSessionNow(deps)); err == nil {
			return nil
		}
	}
	clearSessionCookie(w)
	return nil
}

// notifyBackchannelForSnapshot hands one back-channel logout fan-out to
// the coordinator per distinct subject in the pre-delete snapshot.
//
// The unit of a back-channel logout token is the subject, not the browser
// session: this OP deliberately issues subject-only logout tokens (no
// sid), so N browser sessions of one account in a chooser group would
// otherwise produce N semantically identical fan-outs. Each RP would
// receive N tokens differing only in jti, and the coordinator's inflight
// budget would be spent N times over — under load that sheds fan-outs
// that other subjects still needed. The sibling token cascade dedupes on
// the same key for the same reason.
//
// The Notice still carries the session id of the first row seen for the
// subject, so an operator correlating the audit stream has a handle on
// the ceremony that produced the fan-out.
func notifyBackchannelForSnapshot(ctx context.Context, deps Deps, snapshot []*store.Session) {
	if deps.Backchannel == nil {
		return
	}
	seen := make(map[string]struct{}, len(snapshot))
	for _, row := range snapshot {
		if row == nil || row.Subject == "" || row.ID == "" {
			continue
		}
		if _, ok := seen[row.Subject]; ok {
			continue
		}
		seen[row.Subject] = struct{}{}
		deps.Backchannel.NotifyDetached(ctx, backchannel.Notice{
			Subject:   row.Subject,
			SessionID: row.ID,
		})
	}
}

// revokeAccessTokens cascades RP-Initiated Logout to the access-token
// substores: every grant the subject currently holds is retired so
// subsequent /userinfo, /introspection, and resource-server validations
// reject the outstanding bearer tokens immediately rather than waiting
// for their exp claim to elapse.
//
// The JWT branch dispatches on [Deps.RevocationStrategy]:
//
//   - [store.RevocationStrategyGrantTombstone] (default): write a
//     [store.GrantTombstone] row per grant. Tokens issued before
//     `RevokedAt` are rejected on next verify; future issuances under
//     the same grant are refused at the token endpoint.
//   - [store.RevocationStrategyJTIRegistry]: flip every shadow row
//     under the grant via [store.AccessTokenRegistry.RevokeByGrant]
//     (the per-JTI path).
//   - [store.RevocationStrategyNone]: skip the JWT cascade; the
//     embedder accepted the RFC 6749 §4.1.2 wiggle.
//
// The opaque branch ([Deps.OpaqueAccessTokens]) runs independently
// for every strategy when the substore is wired — opaque tokens have
// their own per-token state and the JWT-strategy switch does not
// apply to them.
//
// A nil [Deps.Grants] short-circuits both branches — the embedder
// has not opted into the registry surface. The caller keeps logout
// user-visible-successful, but receives any store errors to emit an accurate
// audit event.
//
//nolint:gocognit // The cascade deliberately records independent JWT, opaque, and refresh outcomes per grant.
func revokeAccessTokens(ctx context.Context, deps Deps, subject string) error {
	if deps.Grants == nil {
		return nil
	}
	grants, err := deps.Grants.ListBySubject(ctx, subject)
	if err != nil {
		return fmt.Errorf("list grants: %w", err)
	}
	now := endSessionNow(deps)
	var errs []error
	for _, g := range grants {
		if g == nil || g.ID == "" {
			continue
		}
		if err := revokeJWTAccessTokensForGrant(ctx, deps, g.ID, now); err != nil {
			errs = append(errs, fmt.Errorf("grant %s JWT: %w", g.ID, err))
		}
		if deps.OpaqueAccessTokens != nil {
			if _, err := deps.OpaqueAccessTokens.RevokeByGrant(ctx, g.ID); err != nil {
				errs = append(errs, fmt.Errorf("grant %s opaque: %w", g.ID, err))
			}
		}
		if deps.RefreshTokens != nil {
			if err := deps.RefreshTokens.RevokeByGrant(ctx, g.ID); err != nil {
				errs = append(errs, fmt.Errorf("grant %s refresh: %w", g.ID, err))
			}
		}
	}
	return errors.Join(errs...)
}

// revokeAccessTokensForSnapshot runs the token cascade once per distinct
// subject represented by the pre-delete session snapshot. A chooser group
// can contain several browser sessions for the same subject; repeating the
// grant and refresh-token walks would be both wasteful and capable of turning
// an otherwise harmless idempotent logout into a backend error storm.
func revokeAccessTokensForSnapshot(ctx context.Context, deps Deps, snapshot []*store.Session) error {
	seen := make(map[string]struct{}, len(snapshot))
	var errs []error
	for _, row := range snapshot {
		if row == nil || row.Subject == "" {
			continue
		}
		if _, ok := seen[row.Subject]; ok {
			continue
		}
		seen[row.Subject] = struct{}{}
		if err := revokeAccessTokens(ctx, deps, row.Subject); err != nil {
			errs = append(errs, fmt.Errorf("subject %s: %w", row.Subject, err))
		}
	}
	return errors.Join(errs...)
}

// revokeJWTAccessTokensForGrant applies the JWT cascade for one grant
// per the configured strategy. The function is the per-grant body of
// [revokeAccessTokens]; it is split out so the strategy switch is
// readable next to the cascade order.
func revokeJWTAccessTokensForGrant(
	ctx context.Context,
	deps Deps,
	grantID string,
	now time.Time,
) error {
	return endpointsupport.RevokeJWTAccessTokensByGrant(ctx, endpointsupport.JWTGrantCascadeOpts{
		AccessTokens:       deps.AccessTokens,
		GrantRevocations:   deps.GrantRevocations,
		RevocationStrategy: deps.RevocationStrategy,
	}, grantID, now, tombstoneRetention(deps.AccessTokenTTL), "logout")
}

// tombstoneRetention returns the period a grant tombstone must live
// after [store.RevocationStrategyGrantTombstone] writes it. The
// window is "AT TTL + 5-minute clock-skew grace"; a zero
// AccessTokenTTL falls back to one hour, which is the project's
// default AT TTL ceiling.
func tombstoneRetention(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return ttl + 5*time.Minute
}

// endSessionNow returns the wall-clock reading the cascade uses for
// tombstone RevokedAt / ExpiresAt. It mirrors the boundary discipline
// of the sibling endpoints: a configured [Deps.Clock] wins; the fall-
// back is [timex.SystemClock] (the single sanctioned wall-clock seam).
func endSessionNow(deps Deps) time.Time {
	if deps.Clock != nil {
		return deps.Clock.Now().UTC()
	}
	return timex.SystemClock.Now().UTC()
}

// readSessionLookup classifies the __Host-oidc_session cookie into one
// of the three [sessionState] outcomes and, when a session resolves,
// pulls out the session id and the authenticated subject.
//
// Only two failures are answers about the session: an unusable cookie
// ([sessions.ErrCookieInvalid] — missing, undecryptable, or bound to a
// foreign chooser group) and a session the store confirmed is gone or
// expired ([sessions.ErrCurrentSessionExpired]). Both prove there is
// nothing to terminate. Everything else — a transport failure, a
// timeout, a backend that answered nothing at all — is a fault: the OP
// asked whether a session exists and did not learn the answer, so it
// may not proceed as though the answer were "no".
func readSessionLookup(r *http.Request, deps Deps) sessionLookup {
	c, err := r.Cookie(cookie.SessionProfile.Name)
	if err != nil || c == nil || c.Value == "" {
		return sessionLookup{state: sessionAbsent}
	}
	active, err := deps.Sessions.Resolve(r.Context(), c.Value)
	if err != nil {
		if errors.Is(err, sessions.ErrCookieInvalid) || errors.Is(err, sessions.ErrCurrentSessionExpired) {
			return sessionLookup{state: sessionAbsent}
		}
		return sessionLookup{state: sessionStoreUnavailable, err: err}
	}
	if active == nil || active.Session == nil {
		// The manager folds a missing row into ErrCurrentSessionExpired,
		// so reaching here means it broke its own contract. Treat the
		// silence as a fault: nothing here proves the session is gone.
		return sessionLookup{state: sessionStoreUnavailable, err: errSessionUnanswered}
	}
	return sessionLookup{
		state: sessionActive,
		fingerprint: sessionFingerprint{
			sessionID:      active.Session.ID,
			subject:        active.Session.Subject,
			chooserGroupID: active.Session.ChooserGroupID,
		},
	}
}

// errSessionUnanswered marks the contract violation of a session
// manager that reports neither a session nor an error.
var errSessionUnanswered = errors.New("endsession: session manager returned no session and no error")

// errSessionNotDestroyed reports that the destructive workflow could not
// establish that the requested sessions are gone. It stands in for the
// unreadable-store case, where no per-row deletion error exists but the
// OP equally cannot claim the sign-out happened.
var errSessionNotDestroyed = errors.New("endsession: session termination could not be confirmed")

// clearSessionCookie writes a Set-Cookie header that retires the
// session cookie. Errors during construction are swallowed: a failure
// here is a programming bug (the profile is a package constant) and
// surfacing it would mask the original response we were emitting.
// Mirrors authorizeendpoint.clearCookie.
func clearSessionCookie(w http.ResponseWriter) {
	if c, err := cookie.Clear(cookie.SessionProfile); err == nil {
		http.SetCookie(w, c)
	}
}

// setSessionCookie writes a newly sealed session payload. It is used by the
// current-session logout path when the manager has rebound the browser to a
// surviving chooser sibling.
//
// expiresAt is the sibling's server-side expiry and now the endpoint's clock
// reading; [cookie.BuildSession] requires both so the rebound cookie cannot be
// handed a browser lifetime longer than the session it was just bound to. A
// sibling with nothing left returns [cookie.ErrSessionExpired] and the caller
// clears the cookie instead.
func setSessionCookie(w http.ResponseWriter, value string, expiresAt, now time.Time) error {
	c, err := cookie.BuildSession(value, expiresAt, now)
	if err != nil {
		return err
	}
	http.SetCookie(w, c)
	return nil
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
		writeLoggedOutPage(w, resolveLoggedOutPage(r, deps, f))
		return
	}
	target, ok := buildPostLogoutRedirect(f.req.postLogout, f.req.state)
	if !ok {
		writeLoggedOutPage(w, resolveLoggedOutPage(r, deps, f))
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

// isFormContent reports whether ct is application/x-www-form-urlencoded,
// tolerating optional parameters. Mirrors the helper in the sibling
// endpoints so the form-content contract stays uniform.
func isFormContent(ct string) bool {
	return endpointsupport.IsFormContent(ct)
}
