package endsession_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/endsession"
)

func TestOpaqueOrigin_EndSession_400AndCallback(t *testing.T) {
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
			name:      "null origin with mixed-case fetch metadata",
			headers:   map[string]string{"Origin": " null ", "Sec-Fetch-Site": "Same-Origin"},
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
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			h := mountVariant(newHarness(t), func(d *endsession.Deps) {
				d.OnOpaqueOrigin = func() { calls.Add(1) }
			})
			sessionCookie, _ := h.issueSession(t)
			getResp := h.doGET(t, url.Values{}, sessionCookie)
			defer getResp.Body.Close()
			_ = readBody(t, getResp)
			token := readConfirmCookie(getResp)

			form := url.Values{"logout_csrf": {token}}
			addConfirmationGroup(t, h, form, sessionCookie)
			r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, h.endSessionPath, strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			for k, v := range row.headers {
				r.Header.Set(k, v)
			}
			r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessionCookie})
			r.AddCookie(&http.Cookie{Name: cookie.LogoutCSRFProfile.Name, Value: token})
			w := httptest.NewRecorder()
			h.handler.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d want 400", w.Code)
			}
			if got := calls.Load(); got != row.wantCalls {
				t.Errorf("OnOpaqueOrigin calls = %d, want %d", got, row.wantCalls)
			}
		})
	}
}
