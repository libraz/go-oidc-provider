package op_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/store"
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

// fetchDiscovery GETs one discovery URL and returns the raw body. A URL that
// serves no document fails the test naming the URL: a relying party deriving
// it receives a 404 in place of the OP metadata.
func fetchDiscovery(tb testing.TB, url string) (body string, ok bool) {
	tb.Helper()
	resp := httpGet(tb, url)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		tb.Fatalf("read discovery body at %s: %v", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		tb.Errorf("GET %s = %d, want 200: the discovery document must answer at this URL", url, resp.StatusCode)
		return "", false
	}
	return string(raw), true
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

func TestIntegration_Discovery_FAPIProfileAdvertisesRequirePAR(t *testing.T) {
	t.Parallel()

	_, base := startProvider(t, op.WithProfile(profile.FAPI2Baseline))
	resp := httpGet(t, base+"/.well-known/openid-configuration")
	defer resp.Body.Close()

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, _ := doc["pushed_authorization_request_endpoint"].(string); got != validIssuer+"/oidc/par" {
		t.Errorf("par_endpoint=%v want %s/oidc/par", doc["pushed_authorization_request_endpoint"], validIssuer)
	}
	if got, _ := doc["require_pushed_authorization_requests"].(bool); !got {
		t.Fatalf("require_pushed_authorization_requests=%v want true; doc=%v", doc["require_pushed_authorization_requests"], doc)
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

// TestIntegration_PathIssuerRoutesAdvertisedEndpoints pins that every
// endpoint the discovery document advertises is routed, and that the document
// itself answers at every path an issuer is discovered at. An issuer carrying
// a path has two such paths: the RFC 8414 §3 form that inserts the well-known
// suffix ahead of the issuer path, and the OpenID Connect Discovery 1.0 §4
// form that appends it to the issuer, which is what standard relying-party
// libraries request. Both must return the same document.
func TestIntegration_PathIssuerRoutesAdvertisedEndpoints(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		issuer         string
		mountPrefix    string
		discoveryPaths []string
		endpointBase   string
	}{
		{
			name:           "root issuer default mount",
			issuer:         validIssuer,
			mountPrefix:    "/oidc",
			discoveryPaths: []string{"/.well-known/openid-configuration"},
			endpointBase:   "/oidc",
		},
		{
			name:           "root issuer custom mount",
			issuer:         validIssuer,
			mountPrefix:    "/authz",
			discoveryPaths: []string{"/.well-known/openid-configuration"},
			endpointBase:   "/authz",
		},
		{
			name:        "path issuer default mount",
			issuer:      validIssuer + "/tenant",
			mountPrefix: "/oidc",
			discoveryPaths: []string{
				"/.well-known/openid-configuration/tenant",
				"/tenant/.well-known/openid-configuration",
			},
			endpointBase: "/tenant/oidc",
		},
		{
			name:        "path issuer custom mount",
			issuer:      validIssuer + "/tenant",
			mountPrefix: "/authz",
			discoveryPaths: []string{
				"/.well-known/openid-configuration/tenant",
				"/tenant/.well-known/openid-configuration",
			},
			endpointBase: "/tenant/authz",
		},
		{
			name:        "nested path issuer",
			issuer:      validIssuer + "/idp/tenant1",
			mountPrefix: "/oidc",
			discoveryPaths: []string{
				"/.well-known/openid-configuration/idp/tenant1",
				"/idp/tenant1/.well-known/openid-configuration",
			},
			endpointBase: "/idp/tenant1/oidc",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, base := startProvider(t,
				op.WithIssuer(tc.issuer),
				op.WithMountPrefix(tc.mountPrefix),
			)
			var doc map[string]any
			var firstBody string
			for _, discoveryPath := range tc.discoveryPaths {
				body, ok := fetchDiscovery(t, base+discoveryPath)
				if !ok {
					continue
				}
				if firstBody == "" {
					firstBody = body
					if err := json.Unmarshal([]byte(body), &doc); err != nil {
						t.Fatalf("decode discovery at %s: %v", discoveryPath, err)
					}
					continue
				}
				if body != firstBody {
					t.Errorf("discovery at %s returned a different document than %s", discoveryPath, tc.discoveryPaths[0])
				}
			}
			if doc == nil {
				t.Fatalf("no discovery path served a document")
			}

			wantPaths := map[string]string{
				"authorization_endpoint": tc.endpointBase + "/auth",
				"token_endpoint":         tc.endpointBase + "/token",
				"userinfo_endpoint":      tc.endpointBase + "/userinfo",
				"jwks_uri":               tc.endpointBase + "/jwks",
				"end_session_endpoint":   tc.endpointBase + "/end_session",
			}
			for field, wantPath := range wantPaths {
				advertised, ok := doc[field].(string)
				if !ok {
					t.Errorf("discovery field %s missing", field)
					continue
				}
				endpointSuffix := strings.TrimPrefix(wantPath, tc.endpointBase)
				wantAdvertised := tc.issuer + tc.mountPrefix + endpointSuffix
				if advertised != wantAdvertised {
					t.Errorf("%s=%q want %q", field, advertised, wantAdvertised)
				}
				endpointResp := httpGet(t, base+wantPath)
				if endpointResp.StatusCode == http.StatusNotFound {
					endpointResp.Body.Close()
					t.Errorf("%s advertised at %s returned 404", field, wantPath)
					continue
				}
				endpointResp.Body.Close()
			}
		})
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

func TestIntegration_UserInfo_CustomScopeClaimsAreWired(t *testing.T) {
	t.Parallel()

	signKey := newTestKey(t, "userinfo-test")
	st := inmem.New()
	st.PutUser(context.Background(), &store.User{
		Subject: "user-1",
		Claims: map[string]any{
			"project_ids": []string{"p-1", "p-2"},
			"email":       "alice@example.com",
		},
	})
	provider, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(st),
		op.WithKeyset(op.Keyset{signKey}),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
		userInfoTokenClient(),
		op.WithScope(op.Scope{
			Name:   "projects:read",
			Public: true,
			Claims: []string{"project_ids"},
		}),
	)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}

	jws, err := tokens.SignAccessToken(tokens.SigningKey{
		KeyID:  signKey.KeyID,
		Signer: signKey.Signer,
	}, tokens.AccessTokenClaims{
		Issuer:    validIssuer,
		Subject:   "user-1",
		Audience:  []string{validIssuer},
		ClientID:  userInfoTokenClientID,
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		JTI:       "at-custom-scope",
		Scope:     []string{"openid", "projects:read"},
	})
	if err != nil {
		t.Fatalf("SignAccessToken: %v", err)
	}

	req := httptest.NewRequestWithContext(context.Background(),
		http.MethodGet, validIssuer+"/oidc/userinfo", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+jws)
	rec := httptest.NewRecorder()
	provider.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := body["project_ids"].([]any)
	if !ok {
		t.Fatalf("project_ids=%T want []any", body["project_ids"])
	}
	if len(got) != 2 || got[0] != "p-1" || got[1] != "p-2" {
		t.Fatalf("project_ids=%v want [p-1 p-2]", got)
	}
	if _, leaked := body["email"]; leaked {
		t.Fatalf("email leaked without email scope: %v", body["email"])
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

// TestIntegration_Discovery_MachineToMachine_OmitsAuthorizeSurfaces
// pins the agreement between the discovery document and the routing
// table for a client_credentials-only OP. Both are derived from the
// same grant predicate, so an advertised authorization_endpoint /
// end_session_endpoint would be a promise the mux cannot keep: a
// relying party that followed it would get a bare 404 with no OAuth
// error body, and an RP that registered a backchannel_logout_uri would
// wait forever for a Logout Token that no session teardown can emit.
func TestIntegration_Discovery_MachineToMachine_OmitsAuthorizeSurfaces(t *testing.T) {
	t.Parallel()

	_, base := startProvider(t, op.WithGrants(grant.ClientCredentials))

	resp := httpGet(t, base+"/.well-known/openid-configuration")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, absent := range []string{
		"authorization_endpoint",
		"end_session_endpoint",
		"backchannel_logout_supported",
	} {
		if got, ok := doc[absent]; ok {
			t.Errorf("%s=%v must be absent when no grant mounts the authorization endpoint", absent, got)
		}
	}
	types, ok := doc["response_types_supported"].([]any)
	if !ok {
		t.Fatalf("response_types_supported=%#v, want a JSON array (RFC 8414 §2 marks it REQUIRED)",
			doc["response_types_supported"])
	}
	if len(types) != 0 {
		t.Errorf("response_types_supported=%v, want [] when no response_type is accepted", types)
	}

	// The routing table must match what the document promised.
	for _, path := range []string{"/oidc/auth", "/oidc/end_session"} {
		unmounted := httpGet(t, base+path)
		func() {
			defer unmounted.Body.Close()
			if unmounted.StatusCode != http.StatusNotFound {
				t.Errorf("GET %s status=%d, want 404 (route must stay unmounted)", path, unmounted.StatusCode)
			}
		}()
	}
}

// TestIntegration_Discovery_AuthorizationCode_AdvertisesAuthorizeSurfaces
// is the positive half: the default grant set mounts /authorize, so the
// same four members must appear and the routes must answer.
func TestIntegration_Discovery_AuthorizationCode_AdvertisesAuthorizeSurfaces(t *testing.T) {
	t.Parallel()

	_, base := startProvider(t)

	resp := httpGet(t, base+"/.well-known/openid-configuration")
	defer resp.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got, _ := doc["authorization_endpoint"].(string); got != validIssuer+"/oidc/auth" {
		t.Errorf("authorization_endpoint=%v want %s/oidc/auth", doc["authorization_endpoint"], validIssuer)
	}
	if got, _ := doc["end_session_endpoint"].(string); got != validIssuer+"/oidc/end_session" {
		t.Errorf("end_session_endpoint=%v want %s/oidc/end_session", doc["end_session_endpoint"], validIssuer)
	}
	if got, _ := doc["backchannel_logout_supported"].(bool); !got {
		t.Errorf("backchannel_logout_supported=%v want true", doc["backchannel_logout_supported"])
	}
	types, _ := doc["response_types_supported"].([]any)
	if len(types) != 1 || types[0] != "code" {
		t.Errorf("response_types_supported=%v want [code]", types)
	}

	// A bare GET carries no client_id, so the authorize handler answers
	// with an error envelope rather than a redirect — anything other
	// than 404 proves the route is mounted.
	mounted := httpGet(t, base+"/oidc/auth")
	defer mounted.Body.Close()
	if mounted.StatusCode == http.StatusNotFound {
		t.Error("GET /oidc/auth returned 404 although discovery advertises the endpoint")
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
		fixtureAuthenticator(),
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
