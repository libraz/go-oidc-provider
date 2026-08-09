package endsession

import (
	"net/http"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/csrf"
)

// confirmTokenField is the hidden form field the interstitial submits
// the CSRF token through. The cookie half of the double submit is
// defined by [cookie.LogoutCSRFProfile].
//
//nolint:gosec // form field name (not a credential value); G101 false positive.
const confirmTokenField = "logout_csrf"

// renderLogoutConfirmation emits the interstitial confirmation page
// for a GET /end_session the CSRF gate could not admit directly — no
// id_token_hint, or a hint issued for a different subject than the one
// the session cookie authenticates. The page is the OP's CSRF defense
// for OIDC RP-Initiated Logout 1.0 §5: such a request is
// indistinguishable from a cross-site <img src> probe, so the OP MUST
// require an explicit user action (a POST submission) before
// terminating the session. The confirmation form double-submits a
// fresh random token through both a __Host- cookie and a hidden form
// field; the POST handler accepts the request only when the two values
// agree.
//
// The request parameters the eventual redirect depends on (client_id,
// post_logout_redirect_uri, state) are echoed into the form as hidden
// fields so the POST round-trip preserves the OIDC contract. client_id
// is taken from the resolved client so a hint-only request still
// carries a client into the POST, where the hint is no longer present
// to identify one.
func renderLogoutConfirmation(w http.ResponseWriter, r *http.Request, f flow) {
	token, err := csrf.NewRandomToken()
	if err != nil {
		// crypto/rand can only fail under exotic conditions (no
		// entropy source) — emit the generic error page so the wire
		// surface is uniform.
		writeLogoutError(w, http.StatusInternalServerError, descInternalError)
		return
	}
	c, err := cookie.Build(cookie.LogoutCSRFProfile, token)
	if err != nil {
		// The profile is a package constant that validates; a failure
		// here is a programming bug, not a request-shaped one.
		writeLogoutError(w, http.StatusInternalServerError, descInternalError)
		return
	}
	http.SetCookie(w, c)
	stampStaticHeaders(w)
	w.WriteHeader(http.StatusOK)
	// buildConfirmationBody passes every interpolated value through
	// htmlEscapeASCII; the static template carries no script tags and
	// no caller-controlled URLs.
	_, _ = w.Write([]byte(buildConfirmationBody(token, confirmationForm{
		action:     formActionPath(r),
		clientID:   confirmationClientID(f),
		postLogout: f.req.postLogout,
		state:      f.req.state,
	})))
}

// confirmationForm carries the values the interstitial template
// interpolates. The struct exists so the substitution order in
// [buildConfirmationBody] is keyed by name rather than by position.
type confirmationForm struct {
	action     string
	clientID   string
	postLogout string
	state      string
}

// confirmationClientID returns the client_id the confirmation form
// carries into the POST. The resolved client wins: a request that
// identified its client through id_token_hint alone has no client_id
// parameter to echo, and the form drops the hint, so without this the
// POST would arrive with no way to resolve a client and
// post_logout_redirect_uri would be rejected. The parameter is the
// fallback for the no-client case, where it is empty anyway.
func confirmationClientID(f flow) string {
	if f.client != nil {
		return f.client.ID
	}
	return f.req.clientID
}

// formActionPath returns the URL the confirmation form POSTs back to.
//
// The value is a relative reference — "./" plus the last segment of
// the request path — which the browser resolves against the document
// it is showing. Two properties matter:
//
//   - The query string is dropped. An empty action re-submits the
//     current URL verbatim, so every parameter the form already
//     carries as a hidden field would arrive a second time as a query
//     parameter, and the endpoint's single-valued-parameter policy
//     treats a repeat as a malformed request.
//   - The prefix is whatever the browser saw. A reverse proxy that
//     serves the OP under a different path prefix than the one the
//     handler observes would break an absolute path; a relative one
//     lands back on the same document either way.
func formActionPath(r *http.Request) string {
	if r == nil || r.URL == nil {
		return "./"
	}
	path := r.URL.EscapedPath()
	slash := strings.LastIndexByte(path, '/')
	if slash < 0 || slash == len(path)-1 {
		return "./"
	}
	return "./" + path[slash+1:]
}

// validateConfirmToken enforces the double-submit invariant on a POST
// /end_session: the request MUST carry both a __Host- CSRF cookie and
// a matching form field, and the two values MUST be equal under
// [csrf.ConstantTimeEqual] — the same comparison the /interaction
// gate applies to its own double submit. The check returns true only
// when both components are present and agree; any disagreement
// (missing cookie, missing form field, length mismatch, byte
// mismatch) collapses onto the same false return so a network
// observer cannot distinguish the failure modes.
//
// The function is invoked by the POST handler whenever the request did
// not already prove intent for the session at hand — no id_token_hint,
// or a hint minted for a different subject. A hint that names the
// session's own subject skips the gate, because only the holder of
// that session's tokens could have produced it.
//
// Unlike the /interaction gate the token carries no HMAC binding: the
// logout confirmation has no server-side record to bind to (no
// interaction uid, no step name), so the cookie is the whole state and
// equality is the whole check.
func validateConfirmToken(r *http.Request) bool {
	c, err := r.Cookie(cookie.LogoutCSRFProfile.Name)
	if err != nil || c == nil || c.Value == "" {
		return false
	}
	got := r.PostForm.Get(confirmTokenField)
	if got == "" {
		return false
	}
	return csrf.ConstantTimeEqual(c.Value, got)
}

// clearConfirmCookie writes a Set-Cookie header that retires the
// CSRF cookie. The handler calls this on the POST success path so the
// token is single-use; a replayed POST against the cleared cookie
// fails the cookie-presence check rather than the constant-time
// compare. Errors during construction are swallowed: a failure here is
// a programming bug (the profile is a package constant) and surfacing
// it would mask the response we were emitting.
func clearConfirmCookie(w http.ResponseWriter) {
	if c, err := cookie.Clear(cookie.LogoutCSRFProfile); err == nil {
		http.SetCookie(w, c)
	}
}

// confirmationBodyTemplate is the static HTML the interstitial
// confirmation page renders. The page is self-contained: no scripts,
// no external resources, and the only caller-controlled values
// (client_id, state, post_logout_redirect_uri) are flowed through
// htmlEscapeASCII before substitution. A submit button labelled "Sign
// out" doubles as the explicit user gesture the CSRF gate requires.
//
// {TOKEN} carries the opaque CSRF token; {CLIENT_ID}, {STATE} and
// {POST_LOGOUT} carry the request parameters the POST round-trip has
// to preserve so the eventual redirect still validates. {ACTION} is
// the request path without query — the browser POSTs back to the same
// endpoint.
const confirmationBodyTemplate = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>Confirm sign-out</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
</head><body>
<h1>Confirm sign-out</h1>
<p>You are about to sign out of this account. Continue?</p>
<form method="post" action="{ACTION}">
<input type="hidden" name="logout_csrf" value="{TOKEN}">
<input type="hidden" name="client_id" value="{CLIENT_ID}">
<input type="hidden" name="state" value="{STATE}">
<input type="hidden" name="post_logout_redirect_uri" value="{POST_LOGOUT}">
<button type="submit">Sign out</button>
</form>
</body></html>
`

// buildConfirmationBody substitutes the dynamic values into
// [confirmationBodyTemplate]. Every interpolated string is escaped
// with [htmlEscapeASCII] so a hostile state / post_logout_redirect_uri
// cannot break out of the attribute context. The template is a pure
// string replace because the input domain is small and predictable;
// pulling html/template would complicate init-time loading without
// adding security at this scope.
func buildConfirmationBody(token string, form confirmationForm) string {
	body := confirmationBodyTemplate
	body = replaceFirst(body, "{ACTION}", htmlEscapeASCII(form.action))
	body = replaceFirst(body, "{TOKEN}", htmlEscapeASCII(token))
	body = replaceFirst(body, "{CLIENT_ID}", htmlEscapeASCII(form.clientID))
	body = replaceFirst(body, "{STATE}", htmlEscapeASCII(form.state))
	body = replaceFirst(body, "{POST_LOGOUT}", htmlEscapeASCII(form.postLogout))
	return body
}

// validateOriginOrReferer reports whether the request's provenance
// headers admit it as a same-site submission. The decision is
// delegated wholesale to [csrf.CheckOrigin] so /end_session and
// /interaction/{uid} answer identically for the same request shape:
// Origin is matched against the configured allowlist, a request
// without Origin falls back to Referer only when Sec-Fetch-Site
// vouches for it as same-origin, and a request carrying neither is
// rejected.
//
// The check is defense-in-depth on top of the CSRF cookie + token: a
// browser running a malicious page cannot forge these headers, so a
// cookie that leaked through some SameSite edge case is still not
// enough to reach the session. It is not a substitute for the cookie
// + token gate.
//
// The allowlist is the OP's own origin set rather than the request's
// Host header. Host is attacker-controllable end-to-end (a forged
// request supplies both Host and Origin), so comparing the two proves
// only that the attacker was self-consistent.
func validateOriginOrReferer(r *http.Request, allow *csrf.Allowlist) bool {
	return csrf.CheckOrigin(r, allow) == nil
}
