package op_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
)

// startProvider boots an [op.Provider] behind an [httptest.Server]. The
// returned base URL excludes the trailing slash so callers can append
// endpoint paths as-is.
func startProvider(tb testing.TB, opts ...op.Option) (provider *op.Provider, baseURL string) {
	tb.Helper()
	provider, err := op.New(append(validBaseOpts(tb), opts...)...)
	if err != nil {
		tb.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	tb.Cleanup(srv.Close)
	return provider, srv.URL
}

// httpGet wraps an [http.Get] with a request-scoped context so the test
// satisfies the noctx lint and cancels in-flight requests on failure.
func httpGet(tb testing.TB, url string) *http.Response {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, http.NoBody)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		tb.Fatalf("GET %s: %v", url, err)
	}
	return resp
}

func TestIntegration_Discovery_DefaultPathsAndShape(t *testing.T) {
	t.Parallel()

	_, base := startProvider(t)

	resp := httpGet(t, base+"/.well-known/openid-configuration")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Cache-Control"); !strings.HasPrefix(got, "public") {
		t.Errorf("Cache-Control=%q must be cacheable", got)
	}

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}

	want := map[string]string{
		"issuer":                 validIssuer,
		"authorization_endpoint": validIssuer + "/oidc/auth",
		"token_endpoint":         validIssuer + "/oidc/token",
		"jwks_uri":               validIssuer + "/oidc/jwks",
	}
	for key, val := range want {
		if got, _ := doc[key].(string); got != val {
			t.Errorf("doc[%q]=%v want %q", key, doc[key], val)
		}
	}
	// PKCE S256 must be advertised even when no feature is explicitly enabled.
	methods, _ := doc["code_challenge_methods_supported"].([]any)
	if len(methods) != 1 || methods[0] != "S256" {
		t.Errorf("code_challenge_methods=%v want [S256]", methods)
	}
	// PAR must NOT be advertised by default.
	if _, ok := doc["pushed_authorization_request_endpoint"]; ok {
		t.Error("PAR endpoint must be absent unless feature enabled")
	}
}

func TestIntegration_Discovery_WithFeaturesAdvertisesEndpoints(t *testing.T) {
	t.Parallel()

	_, base := startProvider(t,
		op.WithFeature(feature.PAR),
		op.WithFeature(feature.Introspect),
	)
	resp := httpGet(t, base+"/.well-known/openid-configuration")
	defer resp.Body.Close()

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, _ := doc["pushed_authorization_request_endpoint"].(string); got != validIssuer+"/oidc/par" {
		t.Errorf("par_endpoint=%v want %s/oidc/par", doc["pushed_authorization_request_endpoint"], validIssuer)
	}
	if got, _ := doc["introspection_endpoint"].(string); got != validIssuer+"/oidc/introspect" {
		t.Errorf("introspection_endpoint=%v", doc["introspection_endpoint"])
	}
}

func TestIntegration_Discovery_RespectsMountPrefix(t *testing.T) {
	t.Parallel()

	_, base := startProvider(t, op.WithMountPrefix("/auth"))
	resp := httpGet(t, base+"/.well-known/openid-configuration")
	defer resp.Body.Close()

	var doc map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&doc)
	if got, _ := doc["authorization_endpoint"].(string); got != validIssuer+"/auth/auth" {
		t.Errorf("authorization_endpoint=%v want %s/auth/auth", doc["authorization_endpoint"], validIssuer)
	}
	if got, _ := doc["jwks_uri"].(string); got != validIssuer+"/auth/jwks" {
		t.Errorf("jwks_uri=%v", doc["jwks_uri"])
	}
}

func TestIntegration_JWKS_ServedAtConfiguredPath(t *testing.T) {
	t.Parallel()

	_, base := startProvider(t)

	resp := httpGet(t, base+"/oidc/jwks")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/jwk-set+json" {
		t.Errorf("Content-Type=%q", got)
	}

	var payload struct {
		Keys []struct {
			Kid string `json:"kid"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			Kty string `json:"kty"`
			Crv string `json:"crv"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.Keys) != 1 {
		t.Fatalf("keys=%d want 1", len(payload.Keys))
	}
	k := payload.Keys[0]
	if k.Kty != "EC" || k.Crv != "P-256" || k.Alg != "ES256" || k.Use != "sig" {
		t.Errorf("key=%+v want EC/P-256/ES256/sig", k)
	}
}

func TestIntegration_UnknownPath_Returns404(t *testing.T) {
	t.Parallel()

	_, base := startProvider(t)

	resp := httpGet(t, base+"/oidc/does-not-exist")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status=%d want 404", resp.StatusCode)
	}
}
