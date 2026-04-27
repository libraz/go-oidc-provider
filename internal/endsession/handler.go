package endsession

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/store"
)

// maxFormBytes caps the size of a POST /end_session request body. The
// endpoint accepts only the form-encoded shape; even a generously
// sized id_token_hint comfortably fits in a few KiB. 64 KiB is well
// above any legitimate payload while bounding memory use against
// pathological inputs (gosec G120).
const maxFormBytes = 64 * 1024

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
func serve(w http.ResponseWriter, r *http.Request, deps Deps) {
	values, ok := readValues(w, r)
	if !ok {
		return
	}
	req := parseRequest(values)
	client, ok := resolveClient(r.Context(), w, deps, req)
	if !ok {
		return
	}
	if !validatePostLogout(w, client, req.postLogout) {
		return
	}
	terminateSession(w, r, deps)
	emitResponse(w, r, req)
}

// readValues enforces the method / content-type / size invariants and
// returns the parsed parameter map. The bool reports whether the
// caller should continue: false means a response was already written.
func readValues(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodGet+", "+http.MethodPost)
		writeLogoutError(w, http.StatusMethodNotAllowed, descMethodNotAllowed)
		return nil, false
	}
	if r.Method == http.MethodPost {
		if !isFormContent(r.Header.Get("Content-Type")) {
			writeLogoutError(w, http.StatusBadRequest, descContentTypeRequired)
			return nil, false
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
		if err := r.ParseForm(); err != nil {
			writeLogoutError(w, http.StatusBadRequest, descMalformedForm)
			return nil, false
		}
		return r.PostForm, true
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
func resolveByIDTokenHint(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	req request,
) (*store.Client, bool) {
	aud, err := verifyIDTokenHint(deps.Keys, req.idTokenHint)
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
		if uri == postLogout {
			return true
		}
	}
	writeLogoutError(w, http.StatusBadRequest, descPostLogoutNotRegistered)
	return false
}

// terminateSession is the success-path side effect: read the session
// cookie, delete the underlying session record, and clear the cookie
// in the response. Failures during the store call are best-effort —
// the user's intent is to log out, and a transient store fault should
// not surface as a 5xx — but the cookie is always cleared so the
// browser stops authenticating future requests with stale state.
func terminateSession(w http.ResponseWriter, r *http.Request, deps Deps) {
	sid := readSessionID(r, deps)
	if sid != "" {
		// Logout is documented as idempotent; ignoring the error here
		// is consistent with the manager's ErrNotFound contract and
		// matches how /authorize treats expired sessions.
		_ = deps.Sessions.Logout(r.Context(), sid)
	}
	clearSessionCookie(w)
}

// readSessionID pulls the session_id out of the __Host-oidc_session
// cookie. A missing cookie / decode failure returns the empty string;
// the caller treats that as "nothing to delete".
func readSessionID(r *http.Request, deps Deps) string {
	c, err := r.Cookie(cookie.SessionProfile.Name)
	if err != nil || c == nil || c.Value == "" {
		return ""
	}
	active, err := deps.Sessions.Resolve(r.Context(), c.Value)
	if err != nil || active == nil || active.Session == nil {
		return ""
	}
	return active.Session.ID
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
func emitResponse(w http.ResponseWriter, r *http.Request, req request) {
	if req.postLogout == "" {
		writeLoggedOutPage(w)
		return
	}
	target := buildPostLogoutRedirect(req.postLogout, req.state)
	http.Redirect(w, r, target, http.StatusFound)
}

// buildPostLogoutRedirect composes the post-logout redirect target.
// The function is split out so the query-merge logic can be unit-
// tested without invoking the HTTP machinery.
func buildPostLogoutRedirect(postLogout, state string) string {
	if state == "" {
		return postLogout
	}
	u, err := url.Parse(postLogout)
	if err != nil {
		// validatePostLogout has already accepted the URI as
		// preregistered; a parse failure here is a programmer bug.
		// Return the original URI unchanged so the audit log surfaces
		// the malformed value.
		return postLogout
	}
	q := u.Query()
	q.Set("state", state)
	u.RawQuery = q.Encode()
	return u.String()
}

// isFormContent reports whether ct is application/x-www-form-urlencoded,
// tolerating optional parameters. Mirrors the helper in the sibling
// endpoints so the form-content contract stays uniform.
func isFormContent(ct string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "application/x-www-form-urlencoded")
}
