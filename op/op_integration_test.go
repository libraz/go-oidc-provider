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
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
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

func TestIntegration_PAREndpointDisabledByDefault_Returns404(t *testing.T) {
	t.Parallel()

	_, base := startProvider(t)

	// /par is registered only when feature.PAR is enabled. Without the
	// flag the route is absent and the OP serves the default 404.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		base+"/oidc/par", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status=%d want 404 when PAR feature is disabled", resp.StatusCode)
	}
}

// TestIntegration_Discovery_RegisteredScopesRespectVisibility wires the
// full op.New → /.well-known/openid-configuration path and confirms the
// scope visibility contract end-to-end: scopes registered with
// Public:true appear in scopes_supported, scopes registered with
// Public:false do
// not. Standard OIDC scopes always appear because the standard-scope
// fill in op.fillStandardScopes is unconditional.
func TestIntegration_Discovery_RegisteredScopesRespectVisibility(t *testing.T) {
	t.Parallel()

	_, base := startProvider(t,
		op.WithScope(op.Scope{Name: "read:projects", Public: true}),
		op.WithScope(op.Scope{Name: "internal:metrics", Public: false}),
		op.WithScope(op.Scope{
			Name:           "billing:write",
			Public:         true,
			AllowedClients: []string{"svc-billing"},
		}),
	)

	resp := httpGet(t, base+"/.well-known/openid-configuration")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}

	rawScopes, _ := doc["scopes_supported"].([]any)
	advertised := make(map[string]struct{}, len(rawScopes))
	for _, s := range rawScopes {
		if name, ok := s.(string); ok {
			advertised[name] = struct{}{}
		}
	}

	// Public custom scopes and every standard scope must appear.
	mustContain := []string{
		"openid", "profile", "email", "address", "phone", "offline_access",
		"read:projects", "billing:write",
	}
	for _, name := range mustContain {
		if _, ok := advertised[name]; !ok {
			t.Errorf("scopes_supported missing %q (got %v)", name, rawScopes)
		}
	}

	// Non-public scopes MUST NOT leak into discovery; that is the
	// entire point of the Public flag.
	if _, leaked := advertised["internal:metrics"]; leaked {
		t.Errorf("scopes_supported leaked private scope internal:metrics: %v", rawScopes)
	}
}

// TestIntegration_Discovery_ClaimsSupported_OmittedByDefault confirms
// that op.WithClaimsSupported is the only seam that surfaces the
// claims_supported field; without it the library leaves the field off
// the wire because the standard claim universe depends on the
// configured user store.
func TestIntegration_Discovery_ClaimsSupported_OmittedByDefault(t *testing.T) {
	t.Parallel()

	_, base := startProvider(t)
	resp := httpGet(t, base+"/.well-known/openid-configuration")
	defer resp.Body.Close()

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v, ok := doc["claims_supported"]; ok {
		t.Errorf("claims_supported must be absent when WithClaimsSupported is not configured, got %v", v)
	}
}

// TestIntegration_Discovery_ClaimsSupported_AdvertisesEmbedderList
// confirms that the embedder's enumerated list round-trips through the
// discovery wire in order, satisfying OIDC Discovery 1.0 §3.
func TestIntegration_Discovery_ClaimsSupported_AdvertisesEmbedderList(t *testing.T) {
	t.Parallel()

	want := []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email", "email_verified"}
	_, base := startProvider(t, op.WithClaimsSupported(want...))
	resp := httpGet(t, base+"/.well-known/openid-configuration")
	defer resp.Body.Close()

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw, ok := doc["claims_supported"].([]any)
	if !ok {
		t.Fatalf("claims_supported = %v (%T), want []any", doc["claims_supported"], doc["claims_supported"])
	}
	if len(raw) != len(want) {
		t.Fatalf("claims_supported len=%d want %d (%v)", len(raw), len(want), raw)
	}
	for i, c := range want {
		if got, _ := raw[i].(string); got != c {
			t.Errorf("claims_supported[%d]=%q want %q", i, got, c)
		}
	}
}

// TestIntegration_Discovery_DCRDisabled_OmitsRegistrationEndpoint
// confirms that the discovery document omits "registration_endpoint"
// (and the auth methods supported list) when WithDynamicRegistration
// is not configured. Advertising the endpoint without serving it would
// be the worst kind of false promise.
func TestIntegration_Discovery_DCRDisabled_OmitsRegistrationEndpoint(t *testing.T) {
	t.Parallel()

	_, base := startProvider(t)
	resp := httpGet(t, base+"/.well-known/openid-configuration")
	defer resp.Body.Close()

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := doc["registration_endpoint"]; ok {
		t.Errorf("registration_endpoint must be absent when DCR is disabled, got %v", doc["registration_endpoint"])
	}
	if _, ok := doc["registration_endpoint_auth_methods_supported"]; ok {
		t.Errorf("registration_endpoint_auth_methods_supported must be absent when DCR is disabled, got %v", doc["registration_endpoint_auth_methods_supported"])
	}
}

// TestIntegration_Discovery_DCREnabled_AdvertisesRegistrationEndpoint
// confirms that enabling [op.WithDynamicRegistration] surfaces the
// /register URL and the {"initial_access_token"} auth methods list in
// the discovery document. Custom store wiring is required because the
// stub store panics when DCR substores are accessed.
func TestIntegration_Discovery_DCREnabled_AdvertisesRegistrationEndpoint(t *testing.T) {
	t.Parallel()

	provider, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(inmem.New()),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		op.WithDynamicRegistration(op.RegistrationOption{}),
	)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	t.Cleanup(srv.Close)

	resp := httpGet(t, srv.URL+"/.well-known/openid-configuration")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	regURL, _ := doc["registration_endpoint"].(string)
	if regURL != validIssuer+"/oidc/register" {
		t.Errorf("registration_endpoint=%v want %s/oidc/register", doc["registration_endpoint"], validIssuer)
	}
	methods, _ := doc["registration_endpoint_auth_methods_supported"].([]any)
	if len(methods) != 1 || methods[0] != "initial_access_token" {
		t.Errorf("registration_endpoint_auth_methods_supported=%v want [initial_access_token]", methods)
	}
}

func TestIntegration_PAREndpointEnabled_AcceptsPost(t *testing.T) {
	t.Parallel()

	_, base := startProvider(t, op.WithFeature(feature.PAR))

	// A POST without body or credentials should reach the handler and
	// return a 401 invalid_client envelope, confirming the route is
	// mounted and the auth pipeline runs.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		base+"/oidc/par", strings.NewReader(""))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status=%d want 401 invalid_client", resp.StatusCode)
	}
}
