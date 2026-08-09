package authorizeendpoint_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/csrf"
)

// spaHarness extends [testHarness] with the SPA wiring fields the
// SPA route tree exercises. The harness reuses every other piece
// of the legacy harness — store, sessions, csrf — so the only
// observable difference between the two is the route shape under
// test.
type spaHarness struct {
	*testHarness
	loginMount string
	staticDir  string
}

// newSPAHarness builds a SPA-mode handler against fresh in-memory
// infrastructure plus a populated StaticDir on the t.TempDir.
// The bundle layout matches Vite output so the asset handler test
// rows look like a real deployment:
//
//	staticDir/
//	  index.html       ← shell
//	  assets/
//	    main.js        ← content-hashed in real builds
//	  .env             ← dotfile (must be denied)
func newSPAHarness(t *testing.T) *spaHarness {
	t.Helper()
	base := newHarness(t)

	staticDir := t.TempDir()
	mustWriteFile(t, filepath.Join(staticDir, "index.html"),
		"<!doctype html><html><body>SHELL</body></html>")
	mustWriteFile(t, filepath.Join(staticDir, "assets", "main.js"),
		"console.log('asset')")
	mustWriteFile(t, filepath.Join(staticDir, ".env"),
		"SECRET=42")

	deps := authorizeendpoint.Deps{
		Clients:            base.store.Clients(),
		Codes:              base.store.AuthorizationCodes(),
		Grants:             base.store.Grants(),
		Interactions:       base.store.Interactions(),
		Sessions:           base.sessionMgr,
		CookieCodec:        base.cookieCodec,
		CSRF:               base.csrfSigner,
		InteractionOrigins: mustOriginAllowlist(t),
		Driver:             base.driver,
		Authn:              base.orchestrator,
		AuthorizePath:      base.authorizePath,
		InteractionPath:    base.interactionPth,
		SPALoginMount:      "/login",
		SPAStaticDir:       staticDir,
		Clock:              base.clock,
	}

	return &spaHarness{
		testHarness: &testHarness{
			handler:        authorizeendpoint.Handler(deps),
			store:          base.store,
			cookieCodec:    base.cookieCodec,
			sessionMgr:     base.sessionMgr,
			csrfSigner:     base.csrfSigner,
			driver:         base.driver,
			orchestrator:   base.orchestrator,
			clock:          base.clock,
			authorizePath:  base.authorizePath,
			interactionPth: base.interactionPth,
		},
		loginMount: deps.SPALoginMount,
		staticDir:  deps.SPAStaticDir,
	}
}

// TestSPA_AuthorizeRedirectsToLoginMount confirms /authorize routes
// the user agent to LoginMount/{uid} instead of the legacy
// /interaction/{uid} surface when SPA wiring is active. The test
// also verifies the interaction cookie is set in the same response
// so the SPA shell handler can authenticate the redirect target on
// the next hop.
func TestSPA_AuthorizeRedirectsToLoginMount(t *testing.T) {
	t.Parallel()

	h := newSPAHarness(t)
	resp := doAuthorizeGET(t, h.testHarness, goodAuthorizeValues())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, h.loginMount+"/") {
		t.Errorf("Location=%q want prefix %s/", loc, h.loginMount)
	}
	// Legacy /oidc/interaction/{uid} prefix MUST NOT be reachable
	// under SPA wiring; the redirect target proves the redirect
	// target moved.
	if strings.HasPrefix(loc, h.interactionPth+"/") {
		t.Errorf("Location=%q still uses legacy InteractionPath %s", loc, h.interactionPth)
	}
	if !hasCookie(resp, cookie.InteractionProfile.Name) {
		t.Errorf("interaction cookie missing: %v", resp.Cookies())
	}
}

// TestSPA_ShellGET_ReturnsIndexHTMLWithHardeningHeaders pins the
// shell handler's success path: with a valid cookie + a
// well-formed UID the response is the StaticDir/index.html bytes
// plus the OP's standard hardening headers. Embedders that wrap
// the SPA in Cloudflare/CloudFront layers can still rely on
// X-Frame-Options DENY and Cache-Control no-store without
// reconfiguring the upstream stack.
func TestSPA_ShellGET_ReturnsIndexHTMLWithHardeningHeaders(t *testing.T) {
	t.Parallel()

	h := newSPAHarness(t)
	uid, cookieVal := primeInteraction(t, h)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.loginMount+"/"+uid, http.NoBody)
	req.AddCookie(&http.Cookie{Name: cookie.InteractionProfile.Name, Value: cookieVal})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "SHELL") {
		t.Errorf("body=%q want it to contain SHELL marker", body)
	}
	checkHeader(t, resp, "X-Frame-Options", "DENY")
	checkHeader(t, resp, "X-Content-Type-Options", "nosniff")
	checkHeader(t, resp, "Pragma", "no-cache")
	// The shell URL carries the interaction uid, so a full referrer must
	// not cross an origin boundary. same-origin (not no-referrer) matches
	// HTMLDriver.Render: no-referrer would make the browser serialize the
	// Origin header of the SPA's own state-changing fetches as "null",
	// which the interaction CSRF gate then rejects.
	checkHeader(t, resp, "Referrer-Policy", "same-origin")
	cc := resp.Header.Get("Cache-Control")
	if cc == "" || !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control=%q want it to include no-store", cc)
	}
}

// TestSPA_ShellGET_RejectsMissingCookie asserts the URL alone is
// not enough to retrieve index.html: without the
// __Host-oidc_interaction cookie the handler MUST return 404 so
// URL-only probing of "is this uid live" cannot succeed.
func TestSPA_ShellGET_RejectsMissingCookie(t *testing.T) {
	t.Parallel()

	h := newSPAHarness(t)
	uid, _ := primeInteraction(t, h)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.loginMount+"/"+uid, http.NoBody)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status=%d want 404", resp.StatusCode)
	}
}

// TestSPA_ShellGET_RejectsMalformedUID asserts that any path
// segment under LoginMount that does not match the
// base64-url-no-pad shape of [uidByteLength] random bytes resolves
// to 404. The check runs before any IO so the handler does not
// double as a probe for the StaticDir contents.
func TestSPA_ShellGET_RejectsMalformedUID(t *testing.T) {
	t.Parallel()

	h := newSPAHarness(t)

	cases := []struct {
		name string
		uid  string
	}{
		{"too_short", "abc"},
		{"too_long", "abcdefghijklmnopqrstuvwxyz"},
		{"contains_dot", "AAAAAAAAAAAAAAAAAAA.AB"},
		{"index_html", "index.html"},
		// "/login/..", "/login/.", and "/login//" are normalised
		// by [http.ServeMux] before the handler runs (the mux
		// returns 301 to the canonical form) so they cannot reach
		// looksLikeUID; those defenses are validated indirectly
		// through the safeFS asset filter.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
				h.loginMount+"/"+tc.uid, http.NoBody)
			w := httptest.NewRecorder()
			h.handler.ServeHTTP(w, req)
			resp := w.Result()
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("uid=%q status=%d want 404", tc.uid, resp.StatusCode)
			}
		})
	}
}

// TestSPA_StateGET_ReturnsPromptJSON exercises the new state path
// shape (LoginMount/state/{uid}) and confirms the JSON envelope
// the legacy /interaction/{uid} surface produced flows through
// unchanged. The orchestrator tick happens in the same code path
// the legacy surface drives, so a shape regression here surfaces
// every prompt-emitting factor.
func TestSPA_StateGET_ReturnsPromptJSON(t *testing.T) {
	t.Parallel()

	h := newSPAHarness(t)
	uid, cookieVal := primeInteraction(t, h)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.loginMount+"/state/"+uid, http.NoBody)
	req.AddCookie(&http.Cookie{Name: cookie.InteractionProfile.Name, Value: cookieVal})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type=%q want application/json", ct)
	}
	body := readJSON(t, resp)
	if _, ok := body["state_ref"]; !ok {
		t.Errorf("response missing state_ref: %v", body)
	}
}

// TestSPA_AssetGET_ServesBundleFile pins the asset handler's
// happy path: a regular file under StaticDir/assets resolves to a
// 200 with the file contents. The handler always stamps
// X-Content-Type-Options: nosniff so a misnamed asset cannot be
// re-typed by a hostile browser.
func TestSPA_AssetGET_ServesBundleFile(t *testing.T) {
	t.Parallel()

	h := newSPAHarness(t)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.loginMount+"/assets/main.js", http.NoBody)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "asset") {
		t.Errorf("body=%q want bundle file contents", body)
	}
	checkHeader(t, resp, "X-Content-Type-Options", "nosniff")
}

// TestSPA_AssetGET_RejectsDotfile guards the safeFS dotfile rule
// at the wire level. An accidentally-committed .env in StaticDir
// MUST resolve to 404 so a misconfigured deployment cannot leak
// secrets through the asset handler.
func TestSPA_AssetGET_RejectsDotfile(t *testing.T) {
	t.Parallel()

	h := newSPAHarness(t)

	// .env is staged at StaticDir root, not under /assets/, so the
	// path the asset handler attempts to resolve is safeFS-rooted
	// at StaticDir itself. The handler already rejects requests
	// that look like an absolute file outside /assets, so here we
	// stage a dotfile *under* /assets/ to exercise the safeFS
	// segment-wise filter directly.
	mustWriteFile(t, filepath.Join(h.staticDir, "assets", ".secret"), "leak")

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.loginMount+"/assets/.secret", http.NoBody)
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status=%d want 404", resp.StatusCode)
	}
}

// TestSPA_LegacyInteractionPath_IsUnreachable confirms the
// /oidc/interaction/{uid} pattern is NOT registered when SPA
// wiring is active. A request that matches the legacy shape MUST
// fall through to the handler's "no route" branch and produce a
// 404. The check protects against a future regression that
// re-mounts both routes simultaneously and exposes the cookie-
// bound state through two paths.
func TestSPA_LegacyInteractionPath_IsUnreachable(t *testing.T) {
	t.Parallel()

	h := newSPAHarness(t)
	uid, cookieVal := primeInteraction(t, h)

	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.interactionPth+"/"+uid, http.NoBody)
	req.AddCookie(&http.Cookie{Name: cookie.InteractionProfile.Name, Value: cookieVal})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("legacy /interaction status=%d want 404 under SPA wiring", resp.StatusCode)
	}
}

// primeInteraction drives /authorize once to mint a fresh
// interaction record and returns the resulting (uid, sealed
// cookie value) pair. The pair is what every shell + state test
// row needs to satisfy verifyInteractionCookie.
func primeInteraction(t *testing.T, h *spaHarness) (uid, cookieVal string) {
	t.Helper()
	resp := doAuthorizeGET(t, h.testHarness, goodAuthorizeValues())
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status=%d want 302", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	uid = strings.TrimPrefix(loc, h.loginMount+"/")
	for _, c := range resp.Cookies() {
		if c.Name == cookie.InteractionProfile.Name {
			cookieVal = c.Value
		}
	}
	if uid == "" || cookieVal == "" {
		t.Fatalf("could not extract uid/cookie from authorize response: loc=%q cookies=%v", loc, resp.Cookies())
	}
	return uid, cookieVal
}

// checkHeader fails the test when the header is missing or
// differs from want. Centralising the assertion keeps the table
// rows shorter and the error message uniform.
func checkHeader(t *testing.T, resp *http.Response, name, want string) {
	t.Helper()
	got := resp.Header.Get(name)
	if got != want {
		t.Errorf("%s = %q, want %q", name, got, want)
	}
}

// mustOriginAllowlist builds the same single-origin allowlist the
// legacy harness in authorize_test.go uses. The wrapper keeps the
// SPA harness self-contained without exposing helpers between
// files (each *_test.go file in the package compiles
// independently for test isolation, so duplicated builders are
// safer than reaching across files).
func mustOriginAllowlist(t *testing.T) *csrf.Allowlist {
	t.Helper()
	allow, err := csrf.NewAllowlist([]string{"https://op.example.com"})
	if err != nil {
		t.Fatalf("csrf.NewAllowlist: %v", err)
	}
	return allow
}

// mustWriteFile writes content to path with intermediate
// directories. The helper duplicates spa_test.go's mustWrite
// because the two test files live in different packages.
func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatalf("MkdirAll(%s): %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}
