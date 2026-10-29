//go:build apiverify

package apiverify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// 36 mounts the OP under /identity on an application mux and guards
// /api/orders with op/rs. The probe fetches tokens itself and checks the
// success path plus the three RFC 6750 refusals.
func TestExample36ResourceServer(t *testing.T) {
	const (
		base      = "http://127.0.0.1:8080"
		resource  = base + "/api"
		clientID  = "orders-client"
		clientPwd = "orders-demo-secret-4f9k"
	)
	p := buildAndStart(t, "../../36-resource-server")
	defer p.kill()

	pollHTTP(t, p, base+"/.well-known/openid-configuration", 20*time.Second)
	client := &http.Client{Timeout: 5 * time.Second}

	// The application keeps its own routes, and its own 404.
	if got := pollHTTP(t, p, base+"/healthz", 5*time.Second); !strings.Contains(got, "ok") {
		t.Fatalf("/healthz body = %q", got)
	}
	nfReq, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/no-such-page", http.NoBody)
	if err != nil {
		t.Fatalf("build GET /no-such-page: %v", err)
	}
	nf, err := client.Do(nfReq)
	if err != nil {
		t.Fatalf("GET /no-such-page: %v", err)
	}
	_ = nf.Body.Close()
	if nf.StatusCode != http.StatusNotFound {
		t.Fatalf("/no-such-page status = %d, want 404", nf.StatusCode)
	}

	token := func(resourceParam, scope string) string {
		t.Helper()
		form := url.Values{"grant_type": {"client_credentials"}, "scope": {scope}}
		if resourceParam != "" {
			form.Set("resource", resourceParam)
		}
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/identity/token", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("build token request: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(clientID, clientPwd)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("token request: %v\n%s", err, p.readLog())
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		var out struct {
			AccessToken string `json:"access_token"`
		}
		if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &out) != nil || out.AccessToken == "" {
			t.Fatalf("token endpoint (scope %q, resource %q) = %d:\n%s", scope, resourceParam, resp.StatusCode, body)
		}
		return out.AccessToken
	}

	call := func(tok string) (int, string, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, base+"/api/orders", nil)
		if err != nil {
			t.Fatalf("build api request: %v", err)
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("api request: %v\n%s", err, p.readLog())
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, resp.Header.Get("WWW-Authenticate"), string(body)
	}

	// Success.
	status, _, body := call(token(resource, "orders:read"))
	if status != http.StatusOK || !strings.Contains(body, `"orders"`) || !strings.Contains(body, "o-1001") {
		t.Fatalf("valid token: status %d body %s\n%s", status, body, p.readLog())
	}

	// No token: 401, a Bearer challenge, no error code (RFC 6750 §3.1).
	status, ch, _ := call("")
	if status != http.StatusUnauthorized || !strings.HasPrefix(ch, "Bearer") || strings.Contains(ch, "error=") {
		t.Fatalf("no token: status %d challenge %q", status, ch)
	}

	// Token without orders:read: 403 insufficient_scope.
	status, ch, _ = call(token(resource, "orders:write"))
	if status != http.StatusForbidden || !strings.HasPrefix(ch, "Bearer") || !strings.Contains(ch, `error="insufficient_scope"`) {
		t.Fatalf("missing scope: status %d challenge %q", status, ch)
	}

	// Token addressed to the issuer, not the API: 401 invalid_token.
	status, ch, _ = call(token("", "orders:read"))
	if status != http.StatusUnauthorized || !strings.HasPrefix(ch, "Bearer") || !strings.Contains(ch, `error="invalid_token"`) {
		t.Fatalf("wrong audience: status %d challenge %q", status, ch)
	}
}
