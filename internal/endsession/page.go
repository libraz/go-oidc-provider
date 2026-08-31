package endsession

import (
	"html"
	"net/http"
	"strings"
)

// Message keys the confirmation page resolves. They are the only two
// user-facing strings this package renders, and the seed catalogue
// carries a translation of each; resolving them is what keeps a
// deployment that ships a non-English locale from serving one English
// page at the end of an otherwise localized ceremony.
const (
	loggedOutTitleKey = "logout.title"
	loggedOutBodyKey  = "logout.body"
)

// Built-in English for the confirmation page, used when no resolver is
// wired (direct callers, embedders that skip i18n) or when the selected
// locale's catalogue answers neither key.
const (
	loggedOutTitleFallback = "You're signed out"
	loggedOutBodyFallback  = "You can close this window."
)

// loggedOutTemplate is the HTML body served when the request validated
// but no post_logout_redirect_uri was supplied. The document is
// self-contained: no scripts, no external resources. The three
// placeholders are filled from the resolved locale and its messages,
// each escaped at the substitution site; nothing caller-controlled
// reaches the page. Embedders that need a richer confirmation page
// mount their own handler in front of /end_session.
const loggedOutTemplate = `<!DOCTYPE html>
<html lang="{LANG}"><head>
<meta charset="utf-8">
<title>{TITLE}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
</head><body>
<h1>{TITLE}</h1>
<p>{BODY}</p>
</body></html>
`

// errorBodyTemplate is the static HTML body served on the error path.
// The {DESC} placeholder is replaced at render time by one of the
// closed-list descriptions in error.go; the page never interpolates
// caller-supplied input.
const errorBodyTemplate = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>Sign-out failed</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
</head><body>
<h1>Sign-out failed</h1>
<p>{DESC}</p>
</body></html>
`

// writeLoggedOutPage emits the confirmation page in the locale the
// resolver selected for this request. The Content-Security-Policy
// header is the strictest possible value compatible with the document
// so a future regression that introduces dynamic content fails closed.
func writeLoggedOutPage(w http.ResponseWriter, page loggedOutPage) {
	stampStaticHeaders(w)
	w.WriteHeader(http.StatusOK)
	// The body is a const template whose three placeholders are each
	// filled by renderLoggedOutBody through html.EscapeString. The only
	// non-constant inputs are the resolved locale tag and two catalogue
	// strings, and a catalogue is embedder-supplied text that
	// [i18n.Resolver.Message] documents as raw and unescaped — escaping
	// it at the substitution site is exactly where that contract puts
	// the responsibility.
	//nolint:gosec // G705: every interpolated value is html-escaped in renderLoggedOutBody.
	_, _ = w.Write([]byte(renderLoggedOutBody(page)))
}

// loggedOutPage is the resolved content of the confirmation page. A
// zero value renders the built-in English at lang="en", which is what
// a nil resolver produces.
type loggedOutPage struct {
	locale string
	title  string
	body   string
}

// renderLoggedOutBody substitutes the resolved strings into the static
// template. Every value is HTML-escaped here rather than at the
// resolver boundary, because a catalogue is embedder-supplied text and
// [i18n.Resolver.Message] documents its return as raw, unescaped.
func renderLoggedOutBody(page loggedOutPage) string {
	locale := page.locale
	if locale == "" {
		locale = "en"
	}
	title := page.title
	if title == "" {
		title = loggedOutTitleFallback
	}
	body := page.body
	if body == "" {
		body = loggedOutBodyFallback
	}
	out := replaceFirst(loggedOutTemplate, "{LANG}", html.EscapeString(locale))
	// The title appears twice — <title> and <h1> — so the substitution
	// runs until no placeholder is left rather than exactly once.
	out = strings.ReplaceAll(out, "{TITLE}", html.EscapeString(title))
	return replaceFirst(out, "{BODY}", html.EscapeString(body))
}

// writeLogoutError emits the static error page. The Content-Type and
// CSP are identical to the success page so the wire posture stays
// uniform; only the status code and the visible message differ.
//
// description MUST be one of the constants in error.go — the helper
// trusts the caller to have selected from the closed list. The
// substitution is a single string replace rather than html/template
// because the input domain is tiny and pinning the template to a
// const avoids any risk of init-time loading drift.
func writeLogoutError(w http.ResponseWriter, status int, description string) {
	stampStaticHeaders(w)
	w.WriteHeader(status)
	body := renderErrorBody(description)
	_, _ = w.Write([]byte(body))
}

// renderErrorBody substitutes description into the static error
// template. The function is split out so a future regression that
// changes the substitution rules is easy to test in isolation.
func renderErrorBody(description string) string {
	return replaceFirst(errorBodyTemplate, "{DESC}", htmlEscapeASCII(description))
}

// stampStaticHeaders writes the response headers shared by the
// confirmation and error pages. Centralising the helper keeps the two
// surfaces from drifting.
//
// The framing defenses are not optional on these pages: the interstitial
// carries a one-click submit that destroys the session and cascades a
// revocation, so a same-site framer could UI-redress it into a forced
// sign-out. The sandbox directive constrains what the document itself
// may do and says nothing about who may frame it, so frame-ancestors and
// X-Frame-Options are both stamped, on every exit that writes headers.
func stampStaticHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy",
		"default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'; sandbox allow-forms allow-same-origin")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
}

// replaceFirst returns s with the first occurrence of old replaced by
// new. The helper intentionally avoids strings.Replace's count
// parameter so the call site reads as "exactly one substitution".
func replaceFirst(s, old, replacement string) string {
	i := indexOf(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + replacement + s[i+len(old):]
}

// indexOf is a tiny substring search that avoids importing strings for
// the single call in this file. Keeping the helper local also keeps
// the cyclop budget for the page renderer at zero.
func indexOf(haystack, needle string) int {
	if len(needle) == 0 || len(needle) > len(haystack) {
		return -1
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// htmlEscapeASCII escapes the five HTML metacharacters in s. The
// closed-list descriptions in error.go are pure ASCII without any of
// these characters today, but we run the escape unconditionally so an
// accidental future addition (an apostrophe in a description, say)
// cannot escape the static body context.
func htmlEscapeASCII(s string) string {
	out := make([]byte, 0, len(s))
	for i := range len(s) {
		switch s[i] {
		case '&':
			out = append(out, []byte("&amp;")...)
		case '<':
			out = append(out, []byte("&lt;")...)
		case '>':
			out = append(out, []byte("&gt;")...)
		case '"':
			out = append(out, []byte("&quot;")...)
		case '\'':
			out = append(out, []byte("&#39;")...)
		default:
			out = append(out, s[i])
		}
	}
	return string(out)
}
