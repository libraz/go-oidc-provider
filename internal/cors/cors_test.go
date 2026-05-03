package cors_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/cors"
	"github.com/libraz/go-oidc-provider/internal/csrf"
)

// spyEmitter records every event the wrapper emits. It is the
// minimum surface a test needs to assert on the H-C6 short-circuit
// (the strict preflight returns 204 directly and bypasses every
// inner handler / outer middleware below the wrapper).
type spyEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (s *spyEmitter) Emit(_ context.Context, ev audit.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, ev)
}

func (s *spyEmitter) snapshot() []audit.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]audit.Event, len(s.events))
	copy(out, s.events)
	return out
}

// nextOK returns a handler that responds 200 with a marker body so tests can
// verify the CORS wrapper called through to the next handler.
func nextOK() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("served"))
	})
}

func newAllow(t *testing.T, origins ...string) *csrf.Allowlist {
	t.Helper()
	a, err := csrf.NewAllowlist(origins)
	if err != nil {
		t.Fatalf("NewAllowlist: %v", err)
	}
	return a
}

func newReq(tb testing.TB, method, target string) *http.Request {
	tb.Helper()
	return httptest.NewRequestWithContext(context.Background(), method, target, http.NoBody)
}

func TestStrict_NoOrigin_PassThrough(t *testing.T) {
	t.Parallel()

	h := cors.NewStrict(newAllow(t, "https://app.example.com"), nil).Handler(nextOK())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newReq(t, http.MethodGet, "/x"))
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d want 200", rec.Code)
	}
	if rec.Body.String() != "served" {
		t.Errorf("body=%q want served", rec.Body.String())
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("ACAO must be absent on same-origin request")
	}
}

func TestStrict_Preflight_Allowed(t *testing.T) {
	t.Parallel()

	h := cors.NewStrict(newAllow(t, "https://app.example.com"), nil).Handler(nextOK())
	r := newReq(t, http.MethodOptions, "/oidc/token")
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status=%d want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("ACAO=%q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("ACAC=%q want true", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got != "GET, POST, OPTIONS" {
		t.Errorf("ACAM=%q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); got != "Content-Type, Authorization, DPoP, X-CSRF" {
		t.Errorf("ACAH=%q", got)
	}
	if got := rec.Header().Get("Access-Control-Max-Age"); got != "600" {
		t.Errorf("Max-Age=%q want 600", got)
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary=%q want Origin", got)
	}
}

func TestStrict_Preflight_Rejected(t *testing.T) {
	t.Parallel()

	h := cors.NewStrict(newAllow(t, "https://app.example.com"), nil).Handler(nextOK())
	r := newReq(t, http.MethodOptions, "/oidc/token")
	r.Header.Set("Origin", "https://attacker.example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status=%d want 403", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("ACAO must NOT be set for rejected origin (info leak)")
	}
	// Vary: Origin must still be present; the same URL might be allowed
	// for a different Origin and a shared cache would otherwise poison.
	if rec.Header().Get("Vary") != "Origin" {
		t.Error("Vary: Origin must be set even on rejection")
	}
}

func TestStrict_ActualRequest_Allowed_StampsCORS(t *testing.T) {
	t.Parallel()

	h := cors.NewStrict(newAllow(t, "https://app.example.com"), nil).Handler(nextOK())
	r := newReq(t, http.MethodPost, "/oidc/token")
	r.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Errorf("status=%d want 200 (next handler ran)", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Errorf("ACAO=%q", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("ACAC=%q want true", got)
	}
	if rec.Header().Get("Vary") != "Origin" {
		t.Error("Vary: Origin missing")
	}
}

func TestStrict_ActualRequest_Rejected_NoCORS_StillServes(t *testing.T) {
	t.Parallel()

	h := cors.NewStrict(newAllow(t, "https://app.example.com"), nil).Handler(nextOK())
	r := newReq(t, http.MethodPost, "/oidc/token")
	r.Header.Set("Origin", "https://attacker.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	// The OP still serves the response (the request might be a server-to-
	// server call that incidentally has Origin set) but the browser, on
	// seeing no ACAO, blocks the JS reader. This is the standard CORS
	// failure mode and matches §F.4.
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d want 200 (next still runs)", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("ACAO must NOT be set for rejected origin")
	}
}

func TestStrict_Preflight_BareOptionsPassesThrough(t *testing.T) {
	t.Parallel()

	// A plain OPTIONS without Access-Control-Request-Method is not a
	// preflight; it is a server-capabilities query that the inner handler
	// must answer.
	h := cors.NewStrict(newAllow(t, "https://app.example.com"), nil).Handler(nextOK())
	r := newReq(t, http.MethodOptions, "/x")
	r.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Body.String() != "served" {
		t.Errorf("body=%q want served (next ran)", rec.Body.String())
	}
}

func TestStrict_NilAllowlist_DeniesAllCrossOrigin(t *testing.T) {
	t.Parallel()

	h := cors.NewStrict(nil, nil).Handler(nextOK())
	r := newReq(t, http.MethodOptions, "/x")
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status=%d want 403 (nil allowlist denies all)", rec.Code)
	}
}

func TestPublic_StampsWildcardAndRunsHandler(t *testing.T) {
	t.Parallel()

	h := cors.NewPublic().Handler(nextOK())
	r := newReq(t, http.MethodGet, "/.well-known/openid-configuration")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusOK {
		t.Errorf("status=%d want 200", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("ACAO=%q want *", rec.Header().Get("Access-Control-Allow-Origin"))
	}
	if rec.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Error("Public CORS must NOT advertise credentials (incompatible with *)")
	}
}

func TestPublic_PreflightAccepts(t *testing.T) {
	t.Parallel()

	h := cors.NewPublic().Handler(nextOK())
	r := newReq(t, http.MethodOptions, "/.well-known/openid-configuration")
	r.Header.Set("Origin", "https://anyone.example.com")
	r.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status=%d want 204", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("Public preflight must echo *")
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("Allow-Methods must be set on public preflight")
	}
}

func TestStrict_Preflight_IntersectsRequestedHeaders(t *testing.T) {
	t.Parallel()

	h := cors.NewStrict(newAllow(t, "https://app.example.com"), nil).Handler(nextOK())
	r := newReq(t, http.MethodOptions, "/oidc/token")
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")
	r.Header.Set("Access-Control-Request-Headers", "Content-Type, X-Pwn, Authorization, Cookie")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	got := rec.Header().Get("Access-Control-Allow-Headers")
	// Only the headers the OP actually accepts may be echoed.
	if !strings.Contains(got, "Content-Type") {
		t.Errorf("ACAH=%q must echo Content-Type", got)
	}
	if !strings.Contains(got, "Authorization") {
		t.Errorf("ACAH=%q must echo Authorization", got)
	}
	if strings.Contains(strings.ToLower(got), "x-pwn") {
		t.Errorf("ACAH=%q must NOT echo unsupported X-Pwn", got)
	}
	if strings.Contains(strings.ToLower(got), "cookie") {
		t.Errorf("ACAH=%q must NOT echo Cookie (forbidden header anyway)", got)
	}
}

func TestStrict_Preflight_NoRequestHeaders_FallsBackToStatic(t *testing.T) {
	t.Parallel()

	h := cors.NewStrict(newAllow(t, "https://app.example.com"), nil).Handler(nextOK())
	r := newReq(t, http.MethodOptions, "/oidc/token")
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if got := rec.Header().Get("Access-Control-Allow-Headers"); got != "Content-Type, Authorization, DPoP, X-CSRF" {
		t.Errorf("ACAH=%q want full static list when ACRH absent", got)
	}
}

func TestStrict_Preflight_AllRequestedHeadersUnsupported(t *testing.T) {
	t.Parallel()

	h := cors.NewStrict(newAllow(t, "https://app.example.com"), nil).Handler(nextOK())
	r := newReq(t, http.MethodOptions, "/oidc/token")
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")
	r.Header.Set("Access-Control-Request-Headers", "X-Pwn, X-Other")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	if got := rec.Header().Get("Access-Control-Allow-Headers"); got != "" {
		t.Errorf("ACAH=%q want empty when no requested header is accepted", got)
	}
}

// TestStrict_Preflight_AllowedFiresAuditEvent pins the H-C6 audit
// emission. The strict preflight short-circuit returns 204 directly
// and skips every handler / middleware mounted under the CORS
// wrapper; the audit signal makes the bypass visible to SOC tooling
// regardless of where the embedder placed their middleware in the
// chain. The test covers the happy path (allowed origin) and the
// negative branch (rejected origin) — only the happy path emits.
func TestStrict_Preflight_AllowedFiresAuditEvent(t *testing.T) {
	t.Parallel()

	spy := &spyEmitter{}
	h := cors.NewStrict(newAllow(t, "https://app.example.com"), spy).Handler(nextOK())

	r := newReq(t, http.MethodOptions, "/oidc/token")
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d want 204", rec.Code)
	}

	got := spy.snapshot()
	if len(got) != 1 {
		t.Fatalf("emitter saw %d events, want 1: %#v", len(got), got)
	}
	if got[0].Name != "cors.preflight.allowed" {
		t.Errorf("event=%q want cors.preflight.allowed", got[0].Name)
	}
	if origin, _ := got[0].Extras["origin"].(string); origin != "https://app.example.com" {
		t.Errorf("extras.origin=%q want https://app.example.com", origin)
	}
}

// TestStrict_Preflight_RejectedDoesNotFireAuditEvent confirms a
// preflight whose Origin is not in the allowlist does not fire the
// `cors.preflight.allowed` audit event — the response is 403 and
// SOC tooling should not see a positive admission for a denied
// fetch.
func TestStrict_Preflight_RejectedDoesNotFireAuditEvent(t *testing.T) {
	t.Parallel()

	spy := &spyEmitter{}
	h := cors.NewStrict(newAllow(t, "https://app.example.com"), spy).Handler(nextOK())

	r := newReq(t, http.MethodOptions, "/oidc/token")
	r.Header.Set("Origin", "https://attacker.example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rec.Code)
	}
	if got := spy.snapshot(); len(got) != 0 {
		t.Errorf("rejected preflight emitted %d events, want 0: %#v", len(got), got)
	}
}

// TestStrict_NonPreflightDoesNotFireAuditEvent confirms a regular
// (non-OPTIONS) cross-origin request does not fire the preflight-
// allowed audit event — only the OPTIONS short-circuit branch is
// instrumented.
func TestStrict_NonPreflightDoesNotFireAuditEvent(t *testing.T) {
	t.Parallel()

	spy := &spyEmitter{}
	h := cors.NewStrict(newAllow(t, "https://app.example.com"), spy).Handler(nextOK())

	r := newReq(t, http.MethodPost, "/oidc/token")
	r.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 (next handler ran)", rec.Code)
	}
	if got := spy.snapshot(); len(got) != 0 {
		t.Errorf("non-preflight emitted %d events, want 0: %#v", len(got), got)
	}
}

func TestStrict_VaryDeduplicatedWhenInnerAlreadySet(t *testing.T) {
	t.Parallel()

	// Inner handler stamps "Origin" into Vary as a single comma-joined
	// header. The CORS wrapper must observe the existing value and not
	// duplicate the entry.
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Vary", "Origin")
		w.WriteHeader(http.StatusOK)
	})
	h := cors.NewStrict(newAllow(t, "https://app.example.com"), nil).Handler(inner)
	r := newReq(t, http.MethodGet, "/x")
	r.Header.Set("Origin", "https://app.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)

	got := rec.Header().Values("Vary")
	count := 0
	for _, v := range got {
		for _, t := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(t), "Origin") {
				count++
			}
		}
	}
	if count == 0 {
		t.Errorf("Vary missing Origin: %v", got)
	}
	if count > 1 {
		t.Errorf("Vary contains %d Origin entries: %v", count, got)
	}
}
