package endsession

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/backchannel"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/httpx"
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
	confirmTokenField,
}

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
// flows through without an adapter. The handler does not currently
// read the clock — the verifier deliberately does not enforce exp —
// but the field is plumbed so a future policy that needs the wall
// clock (rate limiting, audit timestamps) can be wired without
// breaking the [Deps] shape.
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

	// Clock supplies the current wall-clock reading. A nil Clock
	// falls back to [internal/timex.SystemClock]; see [Deps.Clock]
	// godoc for why the field exists despite the v1.0 verifier not
	// consulting it.
	Clock Clock

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

	// OpaqueAccessTokens cascades the per-grant opaque-format access
	// tokens (ADR 0024) alongside the JWT cascade. The two cascades
	// run independently because they belong to different substores;
	// failures on either are swallowed (best-effort, mirrors the
	// other store calls in this handler). A nil value disables the
	// opaque cascade — the embedder either has no opaque-AT
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

	// GrantRevocations is the [store.GrantRevocationStore] consulted
	// by the grant-tombstone JWT access-token revocation strategy
	// (ADR 0025). The /end_session handler writes a per-grant
	// tombstone here for each affected grant so the cascade is one
	// row per grant rather than one row per AT under that grant. A
	// nil value disables the substore and the handler falls back to
	// whichever legacy behaviour [RevocationStrategy] selects.
	GrantRevocations store.GrantRevocationStore

	// RevocationStrategy selects the JWT access-token revocation
	// shape (ADR 0025). The zero value is
	// [store.RevocationStrategyGrantTombstone], which is the
	// documented default; the library wires this from
	// [op.WithAccessTokenRevocationStrategy].
	RevocationStrategy store.AccessTokenRevocationStrategy

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
func Handler(deps Deps) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, deps)
	})
}

// request carries the parsed parameters the handler operates on. The
// fields mirror the OIDC RP-Initiated Logout 1.0 §2 wire shape minus
// the parameters v1.0 ignores entirely (logout_hint, ui_locales —
// see the package godoc for why). Adding the ignored fields back is
// purely additive when the library grows a chooser UX surface.
type request struct {
	idTokenHint string
	clientID    string
	postLogout  string
	state       string
}

// serve is the request-scoped entry point. It validates the shape,
// resolves the requesting client, terminates the session, and emits
// the response. Decomposing the body keeps the function under the
// project's gocognit / cyclop caps.
//
// The serve flow forks on the presence of id_token_hint:
//
//   - With a valid hint, the hint itself proves the requester
//     possesses an OP-signed token bound to the requesting client.
//     Both GET and POST are accepted directly.
//   - Without a hint, an unauthenticated GET is indistinguishable
//     from a cross-site CSRF probe (e.g. <img src=...>). The handler
//     emits an interstitial confirmation page on GET and requires a
//     POST carrying a double-submit __Host- CSRF token before the
//     session is terminated. This is the OIDC RP-Initiated Logout
//     1.0 §5 plus an OWASP-grade CSRF defense.
func serve(w http.ResponseWriter, r *http.Request, deps Deps) {
	values, ok := readValues(w, r)
	if !ok {
		return
	}
	if _, single := httpx.FirstDuplicateParameter(values, endSessionSingleValuedParams); !single {
		writeLogoutError(w, http.StatusBadRequest, descDuplicateParameter)
		return
	}
	req := parseRequest(values)
	if !validateRequestBounds(w, req) {
		return
	}
	client, ok := resolveClient(r.Context(), w, deps, req)
	if !ok {
		return
	}
	if !validatePostLogout(w, client, req.postLogout) {
		return
	}
	if !enforceCSRFGate(w, r, req) {
		return
	}
	terminateSession(w, r, deps)
	emitResponse(w, r, req)
}

// validateRequestBounds enforces the per-parameter size caps the
// /end_session endpoint applies to mitigate amplification / log-leak
// attacks against the post-logout redirect target. v0.x bounds:
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

// enforceCSRFGate is the CSRF guard for the hint-less branch of the
// /end_session flow. The function returns true when the caller may
// proceed to terminateSession, false when the response has already
// been written (interstitial page on GET, error on a forged POST).
//
// The gate fires only when id_token_hint is absent: a hint-bearing
// request has already proven the caller possesses an OP-signed token
// for the requesting client, which a cross-site script cannot forge.
//
// On a hint-less GET the function renders the interstitial
// confirmation page (HTTP 200) and returns false so the caller
// stops without touching the session. On a hint-less POST the
// function validates the double-submit __Host- CSRF cookie + form
// field plus the Origin / Referer header; any failure produces a
// 400 error page and returns false.
func enforceCSRFGate(w http.ResponseWriter, r *http.Request, req request) bool {
	if req.idTokenHint != "" {
		return true
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		renderLogoutConfirmation(w, r, req)
		return false
	}
	if !validateOriginOrReferer(r) {
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
		if err := r.ParseForm(); err != nil { //nolint:gosec // body bounded by LimitFormBody above
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
// [request]. The OIDC RP-Initiated Logout 1.0 §2 parameters
// "logout_hint" and "ui_locales" are intentionally not extracted:
// v1.0 has no UX surface that would consume them, and storing the
// values would only invite a future regression that surfaces them
// through a log line or audit record without sanitisation.
func parseRequest(v url.Values) request {
	return request{
		idTokenHint: v.Get("id_token_hint"),
		clientID:    v.Get("client_id"),
		postLogout:  v.Get("post_logout_redirect_uri"),
		state:       v.Get("state"),
	}
}

// resolveClient identifies the requesting client from the supplied
// id_token_hint and / or client_id. The function returns nil when no
// client can be identified and that absence is acceptable (no hint
// and no post_logout_redirect_uri); otherwise it writes the error
// response and returns false.
//
// Resolution order:
//
//  1. id_token_hint present: verify signature, extract aud. If
//     client_id is also present and differs from aud, fail.
//  2. Only client_id present: look it up.
//  3. Neither present: succeed with a nil client.
func resolveClient(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	req request,
) (*store.Client, bool) {
	switch {
	case req.idTokenHint != "":
		return resolveByIDTokenHint(ctx, w, deps, req)
	case req.clientID != "":
		return resolveByClientID(ctx, w, deps, req.clientID)
	default:
		return nil, true
	}
}

// resolveByIDTokenHint verifies the id_token_hint signature, extracts
// the aud claim, optionally cross-checks the client_id parameter, and
// looks the resulting client up in the registry.
//
// The verifier consults [Deps.Clock] (or [timex.SystemClock] as a
// fallback) so the iat-age cap inside [verifyIDTokenHint] is testable
// against a fixed clock and consistent with the rest of the handler's
// time references.
func resolveByIDTokenHint(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	req request,
) (*store.Client, bool) {
	aud, err := verifyIDTokenHint(deps.Keys, deps.Issuer, req.idTokenHint, hintNow(deps.Clock))
	if err != nil {
		writeLogoutError(w, http.StatusBadRequest, descIDTokenInvalid)
		return nil, false
	}
	if req.clientID != "" && req.clientID != aud {
		writeLogoutError(w, http.StatusBadRequest, descClientIDDisagrees)
		return nil, false
	}
	return resolveByClientID(ctx, w, deps, aud)
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

// terminateSession is the success-path side effect: read the session
// cookie, delete the underlying session record, dispatch a
// back-channel logout fan-out to the affected RPs, and clear the
// cookie in the response. Failures during the store call are best-
// effort — the user's intent is to log out, and a transient store
// fault should not surface as a 5xx — but the cookie is always
// cleared so the browser stops authenticating future requests with
// stale state.
func terminateSession(w http.ResponseWriter, r *http.Request, deps Deps) {
	sid, subject := readSessionFingerprint(r, deps)
	if sid != "" {
		// Logout is documented as idempotent; ignoring the error here
		// is consistent with the manager's ErrNotFound contract and
		// matches how /authorize treats expired sessions.
		_ = deps.Sessions.Logout(r.Context(), sid)
		deps.audit().Emit(r.Context(), audit.Event{
			Name:      "session.destroyed",
			Level:     audit.LevelInfo,
			Message:   "session destroyed",
			ActorID:   subject,
			SessionID: sid,
		})
	}
	if subject != "" {
		revokeAccessTokens(r.Context(), deps, subject)
		if deps.Backchannel != nil {
			// Back-channel fan-out is best-effort: per-RP failures
			// are recorded as audit events inside the coordinator
			// so a broken downstream cannot stall the user-visible
			// logout.
			_, _ = deps.Backchannel.Notify(r.Context(), backchannel.Notice{
				Subject:   subject,
				SessionID: sid,
			})
		}
	}
	clearSessionCookie(w)
}

// revokeAccessTokens cascades RP-Initiated Logout to the access-token
// substores: every grant the subject currently holds is retired so
// subsequent /userinfo, /introspection, and resource-server validations
// reject the outstanding bearer tokens immediately rather than waiting
// for their exp claim to elapse.
//
// The JWT branch dispatches on [Deps.RevocationStrategy] (ADR 0025):
//
//   - [store.RevocationStrategyGrantTombstone] (default): write a
//     [store.GrantTombstone] row per grant. Tokens issued before
//     `RevokedAt` are rejected on next verify; future issuances under
//     the same grant are refused at the token endpoint.
//   - [store.RevocationStrategyJTIRegistry]: flip every shadow row
//     under the grant via [store.AccessTokenRegistry.RevokeByGrant]
//     (the ADR 0013 path).
//   - [store.RevocationStrategyNone]: skip the JWT cascade; the
//     embedder accepted the RFC 6749 §4.1.2 wiggle.
//
// The opaque branch ([Deps.OpaqueAccessTokens]) runs independently for
// every strategy when the substore is wired (ADR 0024) — opaque tokens
// have their own per-token state and the JWT-strategy switch does not
// apply to them.
//
// A nil [Deps.Grants] short-circuits both branches — the embedder
// has not opted into the registry surface. Per-call errors are
// swallowed: the user's intent is to sign out, and a transient store
// fault must not surface as a 5xx.
func revokeAccessTokens(ctx context.Context, deps Deps, subject string) {
	if deps.Grants == nil {
		return
	}
	grants, err := deps.Grants.ListBySubject(ctx, subject)
	if err != nil {
		return
	}
	now := endSessionNow(deps)
	for _, g := range grants {
		if g == nil || g.ID == "" {
			continue
		}
		revokeJWTAccessTokensForGrant(ctx, deps, g.ID, now)
		if deps.OpaqueAccessTokens != nil {
			_, _ = deps.OpaqueAccessTokens.RevokeByGrant(ctx, g.ID)
		}
	}
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
) {
	_ = endpointsupport.RevokeJWTAccessTokensByGrant(ctx, endpointsupport.JWTGrantCascadeOpts{
		AccessTokens:       deps.AccessTokens,
		GrantRevocations:   deps.GrantRevocations,
		RevocationStrategy: deps.RevocationStrategy,
	}, grantID, now, tombstoneRetention(deps.AccessTokenTTL), "logout")
}

// tombstoneRetention returns the period a grant tombstone must live
// after [store.RevocationStrategyGrantTombstone] writes it. The window
// is "AT TTL + 5-minute clock-skew grace" per ADR 0025 §GC; a zero
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

// readSessionFingerprint pulls the session id and the authenticated
// subject out of the __Host-oidc_session cookie. A missing cookie /
// decode failure returns the empty pair; the caller treats that as
// "nothing to terminate".
func readSessionFingerprint(r *http.Request, deps Deps) (sid, subject string) {
	c, err := r.Cookie(cookie.SessionProfile.Name)
	if err != nil || c == nil || c.Value == "" {
		return "", ""
	}
	active, err := deps.Sessions.Resolve(r.Context(), c.Value)
	if err != nil || active == nil || active.Session == nil {
		return "", ""
	}
	return active.Session.ID, active.Session.Subject
}

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
func emitResponse(w http.ResponseWriter, r *http.Request, req request) {
	if req.postLogout == "" {
		writeLoggedOutPage(w)
		return
	}
	target, ok := buildPostLogoutRedirect(req.postLogout, req.state)
	if !ok {
		writeLoggedOutPage(w)
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
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
