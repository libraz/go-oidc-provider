// Package cors implements the two CORS profiles required by
// 02-product-design.md §F.4: a strict per-origin echo for the
// authenticated endpoints (token, userinfo, interaction, session...) and a
// permissive wildcard for the public metadata endpoints (discovery, JWKS).
// The package emits headers only; it does not handle business logic and
// never short-circuits a non-preflight request. Callers wrap their handlers
// in [Strict.Handler] (or [Public.Handler]) and continue serving as normal.
package cors

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/csrf"
)

// preflightMaxAge is the value advertised in Access-Control-Max-Age for
// strict preflights. Ten minutes balances "browser cache the result" and
// "operator can rotate origins quickly".
const preflightMaxAge = 10 * time.Minute

// allowedHeaders is the static list advertised on every strict preflight.
// It deliberately omits proprietary headers — anything outside the list
// requires a config change rather than a runtime override.
const allowedHeaders = "Content-Type, Authorization, DPoP, X-CSRF"

// Strict is the credentialed-CORS layer used on token / userinfo /
// interaction / session / account endpoints. It echoes the request's Origin
// only when the origin is in the configured allowlist; mismatches are
// answered with 403 (for preflights) or no CORS headers at all (for actual
// requests, which the browser then blocks).
type Strict struct {
	allow *csrf.Allowlist
}

// NewStrict builds a [Strict] handler-builder from an allowlist. The
// allowlist may be nil to mean "deny everything cross-origin", which is the
// safe default when no SPA client is registered.
func NewStrict(allow *csrf.Allowlist) *Strict {
	return &Strict{allow: allow}
}

// AllowedMethods is the static list of methods the OP advertises on a
// strict CORS preflight. The §F.4 spec fixes this to GET / POST / OPTIONS;
// callers cannot widen it without a code change.
//
//nolint:gochecknoglobals // Mirrors a fixed §F.4 spec value.
var allowedMethods = []string{
	http.MethodGet,
	http.MethodPost,
	http.MethodOptions,
}

// Handler wraps next with CORS logic. The wrapper:
//  1. For an OPTIONS request with Origin + Access-Control-Request-Method:
//     answer the preflight directly. Allowed origins receive 204 with the
//     full header set; rejected origins receive 403 with no CORS headers.
//  2. For any request with an Origin header: stamp Vary: Origin and, when
//     the origin is allowed, the Access-Control-Allow-* response headers.
//     Then delegate to next so the actual request is served normally.
//  3. For requests without Origin: passthrough.
//
// The wrapper never modifies the request body or methods; it only writes
// response headers.
func (s *Strict) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.TrimSpace(r.Header.Get("Origin"))
		if origin == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Vary: Origin must always be present when the response varies on
		// Origin, even if we end up not echoing the header. Otherwise a
		// shared cache could serve a no-CORS response to a request that
		// did include an allowed origin.
		appendVary(w.Header(), "Origin")

		canon, err := csrf.CanonicalOrigin(origin)
		allowed := err == nil && s.allow.Contains(canon)

		if isPreflight(r) {
			s.servePreflight(w, origin, allowed)
			return
		}
		if allowed {
			s.stampActual(w, origin)
		}
		next.ServeHTTP(w, r)
	})
}

// servePreflight handles the OPTIONS request. Allowed origins get the full
// header set + 204; rejected origins get 403 with no CORS surface (no
// information leak about what *would* have been accepted).
func (s *Strict) servePreflight(w http.ResponseWriter, origin string, allowed bool) {
	if !allowed {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Access-Control-Allow-Methods", strings.Join(allowedMethods, ", "))
	h.Set("Access-Control-Allow-Headers", allowedHeaders)
	h.Set("Access-Control-Max-Age", strconv.Itoa(int(preflightMaxAge.Seconds())))
	w.WriteHeader(http.StatusNoContent)
}

// stampActual writes the response headers required on a non-preflight
// cross-origin request. Browsers consult these to decide whether the JS
// caller may read the response body.
func (s *Strict) stampActual(w http.ResponseWriter, origin string) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Credentials", "true")
}

// Public is the open CORS profile applied to discovery and JWKS. Anyone may
// fetch the metadata, with no credentials, so the response carries
// Access-Control-Allow-Origin: * and omits Access-Control-Allow-Credentials.
type Public struct{}

// NewPublic returns the public CORS handler-builder. It is stateless and a
// constructor exists only for symmetry with [NewStrict].
func NewPublic() *Public { return &Public{} }

// Handler wraps next with the public CORS profile: every response carries
// Access-Control-Allow-Origin: *, every preflight is accepted, and no
// credentials are advertised. This is appropriate only for unauthenticated
// metadata endpoints (discovery / JWKS).
func (*Public) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		// No Allow-Credentials: incompatible with "*" per the CORS spec.
		if isPreflight(r) {
			h := w.Header()
			h.Set("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Content-Type")
			h.Set("Access-Control-Max-Age", strconv.Itoa(int(preflightMaxAge.Seconds())))
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isPreflight reports whether r is a CORS preflight request: an OPTIONS
// request that carries Access-Control-Request-Method. A bare OPTIONS without
// that header is a normal HTTP method query and we let the underlying
// handler answer.
func isPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions &&
		r.Header.Get("Access-Control-Request-Method") != ""
}

// appendVary adds value to the Vary header without duplicating an entry that
// is already present. Multiple Vary tokens are comma-separated per RFC 7231.
func appendVary(h http.Header, value string) {
	existing := h.Get("Vary")
	if existing == "" {
		h.Set("Vary", value)
		return
	}
	for _, v := range strings.Split(existing, ",") {
		if strings.EqualFold(strings.TrimSpace(v), value) {
			return
		}
	}
	h.Set("Vary", existing+", "+value)
}
