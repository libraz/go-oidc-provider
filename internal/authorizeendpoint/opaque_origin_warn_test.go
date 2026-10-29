package authorizeendpoint_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/cookie"
)

func TestOpaqueOrigin_StateRoute_403AndCallback(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name      string
		headers   map[string]string
		wantCalls int32
	}{
		{
			name:      "null origin from same-origin form",
			headers:   map[string]string{"Origin": "null", "Sec-Fetch-Site": "same-origin"},
			wantCalls: 1,
		},
		{
			name:    "null origin without fetch metadata",
			headers: map[string]string{"Origin": "null"},
		},
		{
			name:    "null origin from cross-site",
			headers: map[string]string{"Origin": "null", "Sec-Fetch-Site": "cross-site"},
		},
		{
			name:    "foreign origin",
			headers: map[string]string{"Origin": "https://attacker.example.com", "Sec-Fetch-Site": "same-origin"},
		},
	}
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		for _, row := range rows {
			t.Run(method+"/"+row.name, func(t *testing.T) {
				t.Parallel()
				base := newSPAHarness(t)
				uid, cookieVal := primeInteraction(t, base)

				var calls atomic.Int32
				handler := authorizeendpoint.Handler(authorizeendpoint.Deps{
					Clients:            base.store.Clients(),
					Codes:              base.store.AuthorizationCodes(),
					Grants:             base.store.Grants(),
					Interactions:       base.store.Interactions(),
					Sessions:           base.sessionMgr,
					CookieCodec:        base.cookieCodec,
					CSRF:               base.csrfSigner,
					InteractionOrigins: mustOriginAllowlist(t),
					OnOpaqueOrigin:     func() { calls.Add(1) },
					Driver:             base.driver,
					Authn:              base.orchestrator,
					AuthorizePath:      base.authorizePath,
					InteractionPath:    base.interactionPth,
					SPALoginMount:      base.loginMount,
					SPAStaticDir:       base.staticDir,
					Clock:              base.clock,
				})

				req := httptest.NewRequestWithContext(context.Background(), method,
					base.loginMount+"/state/"+uid, strings.NewReader("{}"))
				for k, v := range row.headers {
					req.Header.Set(k, v)
				}
				req.AddCookie(&http.Cookie{Name: cookie.InteractionProfile.Name, Value: cookieVal})
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusForbidden {
					t.Fatalf("status=%d want 403", w.Code)
				}
				if got := calls.Load(); got != row.wantCalls {
					t.Errorf("OnOpaqueOrigin calls = %d, want %d", got, row.wantCalls)
				}
			})
		}
	}
}
