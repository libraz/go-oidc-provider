package op_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// The interaction ceremony and the OP's API surface do not share a
// trust boundary. A client's redirect_uri origin belongs on the CORS
// allowlist that guards /token and /userinfo — an SPA relying party
// calls those from its callback page — but the ceremony routes carry
// the in-flight CSRF token and the account list of whoever is signing
// in. Echoing Access-Control-Allow-Origin with
// Access-Control-Allow-Credentials to a redirect_uri origin there lets
// a page registered by one client read another client's ceremony;
// SameSite=Lax does not stop it, because a sibling subdomain is
// cross-origin but same-site.
//
// These tests probe the live routes rather than the allowlist
// builders, because the defect is in which allowlist the route is
// wrapped with, not in what either list contains.

const (
	// ceremonyIssuerOrigin is the origin form of validIssuer: the OP
	// serves its own interaction UI from it.
	ceremonyIssuerOrigin = "https://idp.example.com"
	// ceremonyUIOrigin stands for an interaction UI the embedder hosts
	// off-issuer and enumerates through [op.WithCORSOrigins].
	ceremonyUIOrigin = "https://login-ui.example.com"
	// clientRedirectOrigin is a static client's redirect_uri origin. It
	// is neither the issuer nor an enumerated origin, so it reaches the
	// CORS layer only because the client registered it.
	clientRedirectOrigin = "https://spa.example.com"
)

// ceremonyCORSProvider builds a provider whose CORS allowlist is wider
// than its ceremony allowlist: one static client contributes
// clientRedirectOrigin, [op.WithCORSOrigins] contributes
// ceremonyUIOrigin, and the issuer contributes ceremonyIssuerOrigin.
func ceremonyCORSProvider(tb testing.TB, extra ...op.Option) *op.Provider {
	tb.Helper()
	opts := append(validBaseOptsWithInmem(tb),
		op.WithCORSOrigins(ceremonyUIOrigin),
		op.WithStaticClients(op.PublicClient{
			ID:           "spa",
			RedirectURIs: []string{clientRedirectOrigin + "/callback"},
			Scopes:       []string{"openid"},
		}),
	)
	provider, err := op.New(append(opts, extra...)...)
	if err != nil {
		tb.Fatalf("op.New: %v", err)
	}
	return provider
}

// corsHeadersFor sends a credentialed cross-origin GET and returns the
// response headers. The uid in the path need not name a live ceremony:
// the CORS layer wraps the route and decides on the Origin header
// before the handler ever looks at the uid, so a synthetic uid probes
// exactly the header policy under test without staging a ceremony.
func corsHeadersFor(tb testing.TB, srv *httptest.Server, path, origin string) http.Header {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+path, http.NoBody)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Origin", origin)
	resp, err := srv.Client().Do(req)
	if err != nil {
		tb.Fatalf("GET %s from %s: %v", path, origin, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.Header.Clone()
}

// assertCORSDenied fails when the response carries any credentialed
// CORS grant. Both headers are checked: Allow-Origin alone would let a
// regression that keeps the credentials header pass.
func assertCORSDenied(tb testing.TB, h http.Header, what, origin string) {
	tb.Helper()
	if got := h.Get("Access-Control-Allow-Origin"); got != "" {
		tb.Errorf("%s: Access-Control-Allow-Origin = %q for %s; a client's redirect_uri origin "+
			"can read the in-flight ceremony's CSRF token and account list", what, got, origin)
	}
	if got := h.Get("Access-Control-Allow-Credentials"); got != "" {
		tb.Errorf("%s: Access-Control-Allow-Credentials = %q for %s; the ceremony response is "+
			"readable by a non-participant origin", what, got, origin)
	}
}

// assertCORSAllowed fails when the response withholds the credentialed
// CORS grant an admitted ceremony origin depends on.
func assertCORSAllowed(tb testing.TB, h http.Header, what, origin string) {
	tb.Helper()
	if got := h.Get("Access-Control-Allow-Origin"); got != origin {
		tb.Errorf("%s: Access-Control-Allow-Origin = %q, want %q; an admitted ceremony origin "+
			"cannot drive the interaction UI without it", what, got, origin)
	}
	if got := h.Get("Access-Control-Allow-Credentials"); got != "true" {
		tb.Errorf("%s: Access-Control-Allow-Credentials = %q, want \"true\"", what, got)
	}
}

// TestInteractionRoute_CORSHonoursCeremonyAllowlist covers the HTML
// driver's route, where the interaction page is served from the OP
// itself.
func TestInteractionRoute_CORSHonoursCeremonyAllowlist(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(ceremonyCORSProvider(t))
	t.Cleanup(srv.Close)

	const path = "/oidc/interaction/probe-uid"
	assertCORSDenied(t, corsHeadersFor(t, srv, path, clientRedirectOrigin), "GET "+path, clientRedirectOrigin)
	assertCORSAllowed(t, corsHeadersFor(t, srv, path, ceremonyIssuerOrigin), "GET "+path, ceremonyIssuerOrigin)
	assertCORSAllowed(t, corsHeadersFor(t, srv, path, ceremonyUIOrigin), "GET "+path, ceremonyUIOrigin)
}

// TestInteractionRoute_PreflightRejectsClientRedirectOrigin pins the
// preflight half of the same rule. A browser asks before it sends a
// credentialed cross-origin POST, so a 403 here is what actually stops
// the write; the header assertions above stop the read.
func TestInteractionRoute_PreflightRejectsClientRedirectOrigin(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(ceremonyCORSProvider(t))
	t.Cleanup(srv.Close)

	cases := []struct {
		origin     string
		wantStatus int
	}{
		{origin: clientRedirectOrigin, wantStatus: http.StatusForbidden},
		{origin: ceremonyIssuerOrigin, wantStatus: http.StatusNoContent},
		{origin: ceremonyUIOrigin, wantStatus: http.StatusNoContent},
	}
	for _, tc := range cases {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodOptions,
			srv.URL+"/oidc/interaction/probe-uid", http.NoBody)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Origin", tc.origin)
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("preflight from %s: %v", tc.origin, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != tc.wantStatus {
			t.Errorf("preflight from %s: status = %d, want %d", tc.origin, resp.StatusCode, tc.wantStatus)
		}
	}
}

// TestSPAStateRoute_CORSHonoursCeremonyAllowlist covers the SPA mode's
// JSON surface. It carries the prompt envelope — CSRF token, account
// list, client metadata — so it is the highest-value read on the
// ceremony, and the asset route is checked alongside it because an
// off-issuer UI loads the bundle through the same allowlist.
func TestSPAStateRoute_CORSHonoursCeremonyAllowlist(t *testing.T) {
	t.Parallel()

	staticDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(staticDir, "assets"), 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(staticDir, "assets", "main.js"), []byte("export {}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	srv := httptest.NewServer(ceremonyCORSProvider(t,
		op.WithSPAUI(op.SPAUI{LoginMount: "/login", StaticDir: staticDir}),
	))
	t.Cleanup(srv.Close)

	for _, path := range []string{"/login/state/probe-uid", "/login/assets/main.js"} {
		assertCORSDenied(t, corsHeadersFor(t, srv, path, clientRedirectOrigin), "GET "+path, clientRedirectOrigin)
		assertCORSAllowed(t, corsHeadersFor(t, srv, path, ceremonyIssuerOrigin), "GET "+path, ceremonyIssuerOrigin)
		assertCORSAllowed(t, corsHeadersFor(t, srv, path, ceremonyUIOrigin), "GET "+path, ceremonyUIOrigin)
	}
}

// TestAPIRoutes_KeepClientRedirectOriginOnCORS is the other half of the
// invariant: narrowing the ceremony must not narrow the API surface. An
// SPA relying party still calls /token and /userinfo from the page its
// redirect_uri landed on, and that is why the wide allowlist exists.
func TestAPIRoutes_KeepClientRedirectOriginOnCORS(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(ceremonyCORSProvider(t))
	t.Cleanup(srv.Close)

	for _, path := range []string{"/oidc/token", "/oidc/userinfo"} {
		h := corsHeadersFor(t, srv, path, clientRedirectOrigin)
		if got := h.Get("Access-Control-Allow-Origin"); got != clientRedirectOrigin {
			t.Errorf("GET %s: Access-Control-Allow-Origin = %q, want %q; a registered SPA can no "+
				"longer call the API from its callback page", path, got, clientRedirectOrigin)
		}
	}
}

// ceremonyCrossSiteUIOrigin is a login UI on a different registrable
// domain than the issuer. It is what an embedder reaches for after
// reading that a UI on a client's redirect_uri origin belongs on
// [op.WithCORSOrigins] — and it is the case the option's doc now calls
// unsupported, because the ceremony cookies are same-site by design.
const ceremonyCrossSiteUIOrigin = "https://login-ui.example.net"

// crossSiteCeremonyProvider mirrors [ceremonyCORSProvider] with a real
// password login flow, so /authorize hands back a ceremony the built-in
// HTML driver can actually render. The reachability question is about
// which requests reach a live interaction, so the interaction has to be
// live.
func crossSiteCeremonyProvider(tb testing.TB) *op.Provider {
	tb.Helper()
	st := inmem.New()
	provider, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(st),
		op.WithKeyset(validKeyset(tb)),
		op.WithCookieKeys(newRandomCookieKey(tb)),
		op.WithLoginFlow(op.LoginFlow{
			Primary: op.PrimaryPassword{Store: st.UserPasswords()},
		}),
		op.WithCORSOrigins(ceremonyUIOrigin, ceremonyCrossSiteUIOrigin),
		op.WithStaticClients(op.PublicClient{
			ID:           "spa",
			RedirectURIs: []string{clientRedirectOrigin + "/callback"},
			Scopes:       []string{"openid"},
		}),
	)
	if err != nil {
		tb.Fatalf("op.New: %v", err)
	}
	return provider
}

// stageCeremony drives /authorize far enough to have a live interaction
// and returns its path plus the cookies the OP set for it.
func stageCeremony(tb testing.TB, srv *httptest.Server) (string, []*http.Cookie) {
	tb.Helper()

	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	values := url.Values{
		"client_id":             {"spa"},
		"response_type":         {"code"},
		"redirect_uri":          {clientRedirectOrigin + "/callback"},
		"scope":                 {"openid"},
		"state":                 {"state-ceremony-reach"},
		"nonce":                 {"nonce-ceremony-reach"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/oidc/auth?"+values.Encode(), http.NoBody)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		tb.Fatalf("GET /oidc/auth: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		tb.Fatalf("authorize status = %d, want 302", resp.StatusCode)
	}
	location, err := resp.Location()
	if err != nil {
		tb.Fatalf("authorize Location: %v", err)
	}
	if !strings.HasPrefix(location.Path, "/oidc/interaction/") {
		tb.Fatalf("authorize Location = %s, want an interaction path", location)
	}
	return location.Path, resp.Cookies()
}

// ceremonyRequest sends one request to the staged ceremony from origin,
// attaching cookies, and returns the status. Passing no cookies models
// what a browser does for a cross-site UI: __Host-oidc_interaction is
// SameSite=Lax and __Host-oidc_csrf is SameSite=Strict, so neither
// travels on a cross-site fetch or on a cross-site write.
func ceremonyRequest(
	tb testing.TB, srv *httptest.Server, method, path, origin string, cookies []*http.Cookie,
) int {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method, srv.URL+path, http.NoBody)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Origin", origin)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		tb.Fatalf("%s %s from %s: %v", method, path, origin, err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestInteractionRoute_CrossSiteUIOriginCannotDriveTheCeremony fixes the
// boundary [op.WithCORSOrigins] documents. Listing a cross-site login UI
// grants it CORS — the preflight passes and the response headers name it
// — and grants it nothing else: the ceremony cookies are same-site by
// design, so the endpoint never binds the uid to a cookie and answers
// 404 rather than confirming the uid exists.
//
// The test exists to keep that 404 deliberate. It is the single visible
// symptom of an unsupported topology, and a future change that made the
// route answer on a cookie-less request would be a far worse defect than
// the confusion this pins.
func TestInteractionRoute_CrossSiteUIOriginCannotDriveTheCeremony(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(crossSiteCeremonyProvider(t))
	t.Cleanup(srv.Close)

	// CORS is not the blocker: the cross-site origin is admitted here
	// exactly as the same-site sibling is.
	assertCORSAllowed(t,
		corsHeadersFor(t, srv, "/oidc/interaction/probe-uid", ceremonyCrossSiteUIOrigin),
		"GET /oidc/interaction/probe-uid", ceremonyCrossSiteUIOrigin)

	path, cookies := stageCeremony(t, srv)
	if got := ceremonyRequest(t, srv, http.MethodGet, path, ceremonyIssuerOrigin, cookies); got != http.StatusOK {
		t.Fatalf("same-site GET status = %d, want 200; the control arm is broken, not the boundary", got)
	}
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		if got := ceremonyRequest(t, srv, method, path, ceremonyCrossSiteUIOrigin, nil); got != http.StatusNotFound {
			t.Errorf("cross-site %s status = %d, want 404; the ceremony cookies are same-site and the "+
				"endpoint must not answer for a uid it cannot bind to one", method, got)
		}
	}
}
