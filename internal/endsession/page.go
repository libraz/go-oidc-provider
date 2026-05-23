package endsession

import "net/http"

// loggedOutBody is the static HTML body served when the request
// validated but no post_logout_redirect_uri was supplied. The body is
// self-contained: no scripts, no external resources, no caller-
// controlled interpolation. Embedders that need a richer confirmation
// page mount their own handler in front of /end_session.
const loggedOutBody = `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8">
<title>Signed out</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
</head><body>
<h1>You're signed out</h1>
<p>You can close this window.</p>
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

// writeLoggedOutPage emits the v1.0 confirmation page. The
// Content-Security-Policy header is the strictest possible value
// compatible with the document so a future regression that introduces
// dynamic content fails closed.
func writeLoggedOutPage(w http.ResponseWriter) {
	stampStaticHeaders(w)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(loggedOutBody))
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
func stampStaticHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; sandbox allow-forms allow-same-origin")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
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
