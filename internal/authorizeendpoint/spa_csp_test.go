package authorizeendpoint_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/cookie"
)

// spaHandlerWithCSP rebuilds the harness handler over the same store,
// sessions and static dir with SPAContentSecurityPolicy set. The
// interaction cookie from primeInteraction stays valid because the
// cookie codec is shared.
func spaHandlerWithCSP(t *testing.T, h *spaHarness, csp string) http.Handler {
	t.Helper()
	return authorizeendpoint.Handler(authorizeendpoint.Deps{
		Clients:                  h.store.Clients(),
		Codes:                    h.store.AuthorizationCodes(),
		Grants:                   h.store.Grants(),
		Interactions:             h.store.Interactions(),
		Sessions:                 h.sessionMgr,
		CookieCodec:              h.cookieCodec,
		CSRF:                     h.csrfSigner,
		InteractionOrigins:       mustOriginAllowlist(t),
		Driver:                   h.driver,
		Authn:                    h.orchestrator,
		AuthorizePath:            h.authorizePath,
		InteractionPath:          h.interactionPth,
		SPALoginMount:            h.loginMount,
		SPAStaticDir:             h.staticDir,
		SPAContentSecurityPolicy: csp,
		Clock:                    h.clock,
	})
}

func TestSPAShellCSP(t *testing.T) {
	t.Parallel()

	const defaultCSP = "default-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'"
	const customCSP = "default-src 'self'; script-src 'self' https://cdn.example; frame-ancestors 'none'"

	h := newSPAHarness(t)
	uid, cookieVal := primeInteraction(t, h)

	get := func(handler http.Handler, target string, withCookie bool) *http.Response {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
		if withCookie {
			req.AddCookie(&http.Cookie{Name: cookie.InteractionProfile.Name, Value: cookieVal})
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Result()
	}

	t.Run("configured value on the shell", func(t *testing.T) {
		resp := get(spaHandlerWithCSP(t, h, defaultCSP), h.loginMount+"/"+uid, true)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("shell status=%d want 200", resp.StatusCode)
		}
		checkHeader(t, resp, "Content-Security-Policy", defaultCSP)
	})

	t.Run("custom value replaces it", func(t *testing.T) {
		resp := get(spaHandlerWithCSP(t, h, customCSP), h.loginMount+"/"+uid, true)
		defer resp.Body.Close()
		checkHeader(t, resp, "Content-Security-Policy", customCSP)
	})

	t.Run("empty value stamps nothing", func(t *testing.T) {
		resp := get(spaHandlerWithCSP(t, h, ""), h.loginMount+"/"+uid, true)
		defer resp.Body.Close()
		checkHeader(t, resp, "Content-Security-Policy", "")
	})

	t.Run("assets carry none", func(t *testing.T) {
		resp := get(spaHandlerWithCSP(t, h, defaultCSP), h.loginMount+"/assets/main.js", false)
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("asset status=%d want 200", resp.StatusCode)
		}
		checkHeader(t, resp, "Content-Security-Policy", "")
	})
}
