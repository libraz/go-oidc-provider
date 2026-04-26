package httpx

import (
	"net/http"
	"strings"
)

// EnforceMethod writes a 405 Method Not Allowed response (with Allow header)
// when r.Method does not match any of allowed and returns false. Callers
// guard the body of their handler with the result:
//
//	if !httpx.EnforceMethod(w, r, http.MethodPost) {
//	    return
//	}
//
// The first method in allowed is the canonical answer to OPTIONS; CORS /
// Allow headers list every method passed, comma-separated, in the order the
// caller supplied them.
//
// HEAD is implicitly accepted whenever GET is allowed, matching the
// [http.ServeMux] convention.
func EnforceMethod(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	for _, m := range allowed {
		if r.Method == m {
			return true
		}
		if m == http.MethodGet && r.Method == http.MethodHead {
			return true
		}
	}
	w.Header().Set("Allow", buildAllowHeader(allowed))
	return !writeMethodNotAllowed(w)
}

// buildAllowHeader joins the allowed-method list with the canonical
// "GET, HEAD, POST" formatting that browsers and proxies expect.
func buildAllowHeader(allowed []string) string {
	hasGet := false
	for _, m := range allowed {
		if m == http.MethodGet {
			hasGet = true
			break
		}
	}
	if hasGet {
		// Insert HEAD right after GET if absent.
		seen := false
		out := make([]string, 0, len(allowed)+1)
		for _, m := range allowed {
			out = append(out, m)
			if m == http.MethodGet && !seen {
				out = append(out, http.MethodHead)
				seen = true
			}
		}
		return strings.Join(out, ", ")
	}
	return strings.Join(allowed, ", ")
}

// writeMethodNotAllowed writes the 405 body and reports true so callers can
// chain it inline. Returning a bool keeps [EnforceMethod] expression-style.
func writeMethodNotAllowed(w http.ResponseWriter) bool {
	_ = WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed for this endpoint")
	return true
}
