package scenarios_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestAdvisory_EmittedURLsIgnoreHostHeaders asserts that every absolute
// URL the OP emits (discovery, device verification URIs) derives from
// the configured issuer, never from the request Host or forwarding
// headers.
//
// Tracks: GHSA-mchc-246r-6m76 (ZITADEL) — links were built from client-supplied Host / X-Forwarded-Host.
func TestAdvisory_EmittedURLsIgnoreHostHeaders(t *testing.T) {
	t.Parallel()

	const evil = "evil.example"
	p := newDevProvider(t, []string{"openid"})
	issuer := testkit.DefaultIssuer

	poison := func(r *http.Request) {
		r.Host = evil
		r.Header.Set("X-Forwarded-Host", evil)
		r.Header.Set("X-Forwarded-Proto", "http")
		r.Header.Set("Forwarded", "host="+evil+";proto=http")
	}
	do := func(t *testing.T, req *http.Request) (int, string) {
		t.Helper()
		poison(req)
		resp, err := p.tk.HTTPClient(nil).Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if loc := resp.Header.Get("Location"); strings.Contains(loc, evil) {
			t.Errorf("Location=%q derives from a request header", loc)
		}
		if strings.Contains(string(raw), evil) {
			t.Errorf("%s body contains %q: %s", req.URL.Path, evil, raw)
		}
		return resp.StatusCode, string(raw)
	}

	t.Run("discovery", func(t *testing.T) {
		t.Parallel()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
			p.tk.Server.URL+wellKnownOIDC, http.NoBody)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		status, raw := do(t, req)
		if status != http.StatusOK {
			t.Fatalf("status=%d body=%s", status, raw)
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if got, _ := doc["issuer"].(string); got != issuer {
			t.Errorf("issuer=%q want %q", got, issuer)
		}
		checked := 0
		for k, v := range doc {
			if !strings.HasSuffix(k, "_endpoint") && k != "jwks_uri" {
				continue
			}
			s, ok := v.(string)
			if !ok {
				continue
			}
			checked++
			if !strings.HasPrefix(s, issuer) {
				t.Errorf("%s=%q does not start with issuer %q", k, s, issuer)
			}
		}
		if checked == 0 {
			t.Fatalf("no endpoint URLs found in discovery: %v", doc)
		}
	})

	t.Run("device_authorization", func(t *testing.T) {
		t.Parallel()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			p.tk.Server.URL+"/oidc/device_authorization",
			strings.NewReader(url.Values{"scope": {"openid"}}.Encode()))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(p.client.ID, devClientSecret)
		status, raw := do(t, req)
		if status != http.StatusOK {
			t.Fatalf("status=%d body=%s", status, raw)
		}
		var body map[string]any
		if err := json.Unmarshal([]byte(raw), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		for _, k := range []string{"verification_uri", "verification_uri_complete"} {
			s, _ := body[k].(string)
			if s == "" {
				// verification_uri_complete is optional (RFC 8628 §3.2).
				if k == "verification_uri" {
					t.Errorf("%s missing: %v", k, body)
				}
				continue
			}
			if !strings.HasPrefix(s, issuer) {
				t.Errorf("%s=%q does not start with issuer %q", k, s, issuer)
			}
		}
	})
}
