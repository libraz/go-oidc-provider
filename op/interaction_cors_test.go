package op_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
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
