// Package cors implements the two CORS profiles the OP applies: a strict
// per-origin echo for the authenticated endpoints (token, userinfo,
// interaction, session...) and a permissive wildcard for the public
// metadata endpoints (discovery, JWKS).
// The package emits headers only; it does not handle business logic and
// never short-circuits a non-preflight request. Callers wrap their handlers
// in [Strict.Handler] (or [Public.Handler]) and continue serving as normal.
//
// Wrap order: callers MUST place [Strict.Handler] / [Public.Handler]
// outermost on every endpoint that opts into CORS. The strict
// preflight branch answers an OPTIONS+ACRM probe with 204 directly
// and never calls into next, so any audit / rate-limit / metrics
// middleware mounted *inside* the CORS wrapper would silently miss
// the request. The hardening pairs this constraint with the
// `cors.preflight.allowed` audit event ([op.AuditCORSPreflightAllowed])
// so SOC tooling sees the short-circuit even when the embedder's
// middleware order is wrong.
package cors

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
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

// allowedHeadersSet is the lower-cased lookup table for [allowedHeaders].
// It is consulted on every preflight to intersect the request's
// Access-Control-Request-Headers list with the policy: the response only
// echoes the subset the OP actually accepts, so an attacker cannot trick the
// browser into permitting a header (e.g. Cookie) the OP never reads.
//
//nolint:gochecknoglobals // Static derived value mirrors allowedHeaders.
var allowedHeadersSet = func() map[string]struct{} {
	out := make(map[string]struct{}, 4)
	for _, h := range strings.Split(allowedHeaders, ",") {
		out[strings.ToLower(strings.TrimSpace(h))] = struct{}{}
	}
	return out
}()

// Strict is the credentialed-CORS layer used on token / userinfo /
// interaction / session / account endpoints. It echoes the request's Origin
// only when the origin is in the configured allowlist; mismatches are
// answered with 403 (for preflights) or no CORS headers at all (for actual
// requests, which the browser then blocks).
type Strict struct {
	allow   *csrf.Allowlist
	emitter audit.Emitter
}

// NewStrict builds a [Strict] handler-builder from an allowlist. The
// allowlist may be nil to mean "deny everything cross-origin", which is the
// safe default when no SPA client is registered.
//
// emitter is the audit sink the strict preflight short-circuit fires
// through ([op.AuditCORSPreflightAllowed]). A nil emitter is replaced
// with [audit.Discard] so the wrapper still works in unit tests that
// do not assert on audit output.
func NewStrict(allow *csrf.Allowlist, emitter audit.Emitter) *Strict {
	if emitter == nil {
		emitter = audit.Discard()
	}
	return &Strict{allow: allow, emitter: emitter}
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
			s.servePreflight(w, r, origin, allowed)
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
//
// The Access-Control-Allow-Headers value is the intersection of
// [allowedHeadersSet] with the browser's Access-Control-Request-Headers
// list. When the request omits the header the static [allowedHeaders] is
// echoed verbatim (the conservative default that mirrors browser behaviour
// for "no special headers"); when the request lists a header the OP does
// not accept, the unsupported entry is silently dropped from the response so
// the browser's CORS check fails for that specific header without leaking a
// list of known-good names.
//
// On accept the function fires [op.AuditCORSPreflightAllowed] through
// the configured emitter so SOC tooling sees the short-circuit even
// when the embedder's outer middleware (rate-limit, audit) is mounted
// inside the CORS wrapper and would otherwise miss the request.
func (s *Strict) servePreflight(w http.ResponseWriter, r *http.Request, origin string, allowed bool) {
	if !allowed {
		http.Error(w, "origin not allowed", http.StatusForbidden)
		return
	}
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Access-Control-Allow-Methods", strings.Join(allowedMethods, ", "))
	h.Set("Access-Control-Allow-Headers", intersectAllowedHeaders(r.Header.Get("Access-Control-Request-Headers")))
	h.Set("Access-Control-Max-Age", strconv.Itoa(int(preflightMaxAge.Seconds())))
	w.WriteHeader(http.StatusNoContent)
	s.emitter.Emit(emitContext(r), audit.Event{
		Name:    string(auditevent.AuditCORSPreflightAllowed),
		Level:   audit.LevelInfo,
		Message: "strict CORS preflight admitted",
		Extras: map[string]any{
			"origin":         origin,
			"request_method": r.Header.Get("Access-Control-Request-Method"),
			"path":           r.URL.Path,
		},
	})
}

// emitContext returns the request's context, falling back to a fresh
// [context.Background] when the request is constructed without one
// (defensive — production paths always carry a context).
func emitContext(r *http.Request) context.Context {
	if r != nil && r.Context() != nil {
		return r.Context()
	}
	return context.Background()
}

// intersectAllowedHeaders returns the subset of requested headers the OP
// actually accepts, comma-joined, preserving the request's casing for the
// echoed names. An empty request defaults to the full static [allowedHeaders]
// so the existing "browser sent no ACRH" path stays compatible.
func intersectAllowedHeaders(requested string) string {
	requested = strings.TrimSpace(requested)
	if requested == "" {
		return allowedHeaders
	}
	parts := strings.Split(requested, ",")
	out := make([]string, 0, len(parts))
	for _, raw := range parts {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if _, ok := allowedHeadersSet[strings.ToLower(name)]; ok {
			out = append(out, name)
		}
	}
	return strings.Join(out, ", ")
}

// exposedHeaders is the fixed Access-Control-Expose-Headers value
// stamped on every strict-CORS actual response. Without this header a
// browser JS caller cannot read a cross-origin response header even
// when it is present on the wire: DPoP-Nonce carries the RFC 9449 §8
// nonce-retry challenge, WWW-Authenticate carries the error detail a
// public-client SPA needs to branch on, and x-fapi-interaction-id lets
// a FAPI conformant SPA correlate its own logs with the OP's. Omitting
// this header silently breaks the browser-side nonce-retry loop even
// though the server-side contract is otherwise correct.
const exposedHeaders = "DPoP-Nonce, WWW-Authenticate, x-fapi-interaction-id"

// stampActual writes the response headers required on a non-preflight
// cross-origin request. Browsers consult these to decide whether the JS
// caller may read the response body.
func (s *Strict) stampActual(w http.ResponseWriter, origin string) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Credentials", "true")
	h.Set("Access-Control-Expose-Headers", exposedHeaders)
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
		// Vary: Origin even when the response is the static "*",
		// because shared caches (CDN, browser) MUST treat differently
		// when an Origin-aware policy is later swapped in. Cheap
		// insurance against future-policy regressions.
		appendVary(w.Header(), "Origin")
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
