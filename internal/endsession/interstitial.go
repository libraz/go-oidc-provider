package endsession

import (
	"crypto/rand" //nolint:depguard // CSRF token generation; pinned use, allow-list addition deferred to follow-up.
	"crypto/subtle"
	"encoding/base64"
	"net/http"
	"net/url"
	"time"
)

// confirmCookieName is the cookie that carries the CSRF token value
// across the GET → POST round-trip. The cookie is __Host- scoped so it
// is restricted to the OP origin; SameSite=Strict means a cross-site
// POST cannot present the cookie even if the attacker spoofed an
// Origin / Referer. The cookie is short-lived: the user is expected
// to confirm within minutes, and a stale cookie should not linger
// across browsing sessions.
const (
	confirmCookieName = "__Host-oidc_logout_csrf"
	//nolint:gosec // form field name (not a credential value); G101 false positive.
	confirmTokenField = "logout_csrf"
	confirmCookieTTL  = 5 * time.Minute
)

// renderLogoutConfirmation emits the interstitial confirmation page
// for a GET /end_session that arrived without an id_token_hint. The
// page is the OP's CSRF defense for OIDC RP-Initiated Logout 1.0
// §5: with no hint, the request is indistinguishable from a
// cross-site <img src> probe, so the OP MUST require an explicit user
// action (a POST submission) before terminating the session. The
// confirmation form double-submits a fresh random token through both
// a __Host- cookie and a hidden form field; the POST handler accepts
// the request only when the two values agree.
//
// The query-string parameters the original request carried (state,
// post_logout_redirect_uri) are echoed into the form as hidden fields
// so the POST round-trip preserves the OIDC contract for the eventual
// redirect.
func renderLogoutConfirmation(w http.ResponseWriter, _ *http.Request, req request) {
	token, err := newConfirmToken()
	if err != nil {
		// crypto/rand can only fail under exotic conditions (no
		// entropy source) — emit the generic error page so the wire
		// surface is uniform.
		writeLogoutError(w, http.StatusInternalServerError, descMethodNotAllowed)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     confirmCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(confirmCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
	stampStaticHeaders(w)
	w.WriteHeader(http.StatusOK)
	// buildConfirmationBody passes every interpolated value through
	// htmlEscapeASCII; the static template carries no script tags and
	// no caller-controlled URLs. G705 is a false positive here.
	//nolint:gosec // values are htmlEscapeASCII-escaped before substitution.
	_, _ = w.Write([]byte(buildConfirmationBody(token, req)))
}

// validateConfirmToken enforces the double-submit invariant on a POST
// /end_session: the request MUST carry both a __Host- CSRF cookie and
// a matching form field, and the two values MUST be equal under a
// constant-time compare. The check returns true only when both
// components are present and agree; any disagreement (missing cookie,
// missing form field, length mismatch, byte mismatch) collapses onto
// the same false return so a network observer cannot distinguish the
// failure modes.
//
// The function is invoked by the POST handler ONLY when the request
// arrived without an id_token_hint — a hint-bearing POST proves the
// requester possesses a token the OP signed for the requesting client,
// so the additional CSRF gate is unnecessary.
func validateConfirmToken(r *http.Request) bool {
	c, err := r.Cookie(confirmCookieName)
	if err != nil || c == nil || c.Value == "" {
		return false
	}
	got := r.PostForm.Get(confirmTokenField)
	if got == "" {
		return false
	}
	if len(got) != len(c.Value) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(c.Value)) == 1
}

// clearConfirmCookie writes a Set-Cookie header that retires the
// CSRF cookie. The handler calls this on the POST success path so the
// token is single-use; a replayed POST against the cleared cookie
// fails the cookie-presence check rather than the constant-time
// compare.
func clearConfirmCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     confirmCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

// newConfirmToken returns a cryptographically random 32-byte value
// encoded as base64url (no padding). The returned string is suitable
// for both the cookie value and the form field; the encoding is
// URL-safe so the form field round-trips through application/x-www-
// form-urlencoded without escaping.
func newConfirmToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// confirmationBodyTemplate is the static HTML the interstitial
// confirmation page renders. The page is self-contained: no scripts,
// no external resources, and the only caller-controlled values
// (state, post_logout_redirect_uri) are flowed through
// htmlEscapeASCII before substitution. A submit button labelled "Sign
// out" doubles as the explicit user gesture the CSRF gate requires.
//
// {TOKEN} carries the opaque CSRF token; {STATE} and {POST_LOGOUT}
// carry the original query parameters so the POST round-trip
// preserves them. {ACTION} is the request URL without query — the
// browser POSTs back to the same endpoint.
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
func buildConfirmationBody(token string, req request) string {
	body := confirmationBodyTemplate
	body = replaceFirst(body, "{ACTION}", "")
	body = replaceFirst(body, "{TOKEN}", htmlEscapeASCII(token))
	body = replaceFirst(body, "{STATE}", htmlEscapeASCII(req.state))
	body = replaceFirst(body, "{POST_LOGOUT}", htmlEscapeASCII(req.postLogout))
	return body
}

// hostHeaderForReferer extracts the bare host:port component of u.
// Used by [validateOrigin] when comparing the Referer header's parse
// to the request's Host. Returns the empty string on a parse failure
// so the caller falls onto the generic reject path.
func hostHeaderForReferer(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}

// validateOriginOrReferer reports whether the request's Origin or
// Referer header matches the request's own host. The OP serves
// /end_session from the issuer host, so a same-site POST always
// carries Origin (modern browsers) or Referer (older clients)
// pointing at that host. A cross-site POST either omits both headers
// (a hand-crafted curl, ignored) or carries a foreign value (the
// attacker's origin, rejected). The check is defense-in-depth on top
// of the CSRF cookie + token: a browser running a malicious page
// might leak the cookie under SameSite=Lax in some legacy
// configurations, but the Origin / Referer check still rejects the
// request because the script cannot forge those headers. The check is
// not a substitute for the cookie + token gate.
func validateOriginOrReferer(r *http.Request) bool {
	host := r.Host
	if host == "" {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		if hostHeaderForReferer(origin) == host {
			return true
		}
		// A POST that carries a foreign Origin header is rejected
		// outright; treat the absence-or-match check as authoritative.
		return false
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		return hostHeaderForReferer(ref) == host
	}
	// Neither header is present. Treat the request as unverifiable:
	// the confirmation POST is browser-facing and should carry one of
	// these provenance headers before the double-submit token is
	// honoured.
	return false
}
