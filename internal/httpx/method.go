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
// The Allow header lists every method passed, comma-separated, in the order
// the caller supplied them. The response is the plain-text "method not
// allowed" body with the no-store headers every dynamic endpoint carries.
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
	MethodNotAllowed(w, buildAllowHeader(allowed))
	return false
}

// MethodNotAllowed writes the 405 response [EnforceMethod] uses, advertising
// allow verbatim in the Allow header when it is non-empty. Callers whose
// method set is not a plain list (a verb the request did not match yet is
// still routed, or a set that depends on configuration) call it directly.
func MethodNotAllowed(w http.ResponseWriter, allow string) {
	if allow != "" {
		w.Header().Set("Allow", allow)
	}
	StampNoStore(w)
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
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
