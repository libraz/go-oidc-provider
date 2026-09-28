package op_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestIntegration_DCR_FAPI2_RefusesAuthMethodsOutsideProfile holds dynamic
// registration to the same token_endpoint_auth_method set the FAPI 2.0
// profile imposes on every runtime client-authentication site. A method
// outside it, including the default an omitted member resolves to, is
// refused at registration and at RFC 7592 update, so no client can be
// persisted that the token endpoint would then refuse to authenticate.
func TestIntegration_DCR_FAPI2_RefusesAuthMethodsOutsideProfile(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	provider, err := op.New(append(dcrBaseOpts(t, inmem.New(inmem.WithClock(clock)), clock),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithDynamicRegistration(op.RegistrationOption{}),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	t.Cleanup(srv.Close)
	registerURL := srv.URL + "/oidc/register"
	iat := func() string {
		issued, err := provider.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{})
		if err != nil {
			t.Fatalf("IssueInitialAccessToken: %v", err)
		}
		return issued.Value
	}
	metadata := func(method string) map[string]any {
		m := map[string]any{
			"redirect_uris": []string{"https://rp.test.invalid/callback"},
			"jwks_uri":      "https://rp.test.invalid/jwks.json",
		}
		if method != "" {
			m["token_endpoint_auth_method"] = method
		}
		return m
	}

	for _, method := range []string{"", "client_secret_basic", "client_secret_post", "none"} {
		got := postJSON(t, registerURL, iat(), metadata(method))
		if got.status != http.StatusBadRequest || got.body["error"] != "invalid_client_metadata" {
			t.Errorf("POST /register token_endpoint_auth_method=%q: status=%d body=%s, want 400 invalid_client_metadata",
				method, got.status, got.raw)
		}
	}

	created := postJSON(t, registerURL, iat(), metadata("private_key_jwt"))
	if created.status != http.StatusCreated {
		t.Fatalf("POST /register private_key_jwt: status=%d want 201 body=%s", created.status, created.raw)
	}
	clientID, _ := created.body["client_id"].(string)
	rat, _ := created.body["registration_access_token"].(string)
	if clientID == "" || rat == "" {
		t.Fatalf("registration response is missing management credentials: %v", created.body)
	}
	manageURL := registerURL + "/" + clientID

	for _, method := range []string{"", "client_secret_basic", "none"} {
		payload := metadata(method)
		payload["client_id"] = clientID
		got := requestJSON(t, http.MethodPut, manageURL, rat, payload)
		if got.status != http.StatusBadRequest || got.body["error"] != "invalid_client_metadata" {
			t.Errorf("PUT /register/{id} token_endpoint_auth_method=%q: status=%d body=%s, want 400 invalid_client_metadata",
				method, got.status, got.raw)
		}
	}

	read := requestJSON(t, http.MethodGet, manageURL, rat, nil)
	if read.status != http.StatusOK {
		t.Fatalf("GET /register/{id}: status=%d want 200 body=%s", read.status, read.raw)
	}
	if got := read.body["token_endpoint_auth_method"]; got != "private_key_jwt" {
		t.Errorf("persisted token_endpoint_auth_method=%v after refused updates, want private_key_jwt", got)
	}
}

// TestIntegration_FAPI2_ClientSigningAlgsAgreeAcrossSurfaces holds the
// discovery advertisement and dynamic registration to the FAPI 2.0 JWS
// alg set the assertion and request-object verifiers enforce: RS256 is
// neither advertised nor registrable, while PS256 is both.
func TestIntegration_FAPI2_ClientSigningAlgsAgreeAcrossSurfaces(t *testing.T) {
	t.Parallel()

	clock := dcrFixedClock()
	provider, err := op.New(append(dcrBaseOpts(t, inmem.New(inmem.WithClock(clock)), clock),
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.JAR),
		op.WithDynamicRegistration(op.RegistrationOption{}),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	t.Cleanup(srv.Close)

	resp := getJSON(t, srv.URL+"/.well-known/openid-configuration")
	defer resp.Body.Close()
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	want := []any{"PS256", "ES256", "EdDSA"}
	for _, member := range []string{
		"token_endpoint_auth_signing_alg_values_supported",
		"request_object_signing_alg_values_supported",
	} {
		got, _ := doc[member].([]any)
		if !slices.Equal(got, want) {
			t.Errorf("%s = %v, want %v", member, got, want)
		}
	}

	register := func(member, alg string) jsonResponse {
		issued, err := provider.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{})
		if err != nil {
			t.Fatalf("IssueInitialAccessToken: %v", err)
		}
		return postJSON(t, srv.URL+"/oidc/register", issued.Value, map[string]any{ //nolint:gosec // G101 false positive: "private_key_jwt" is the OIDC auth-method name, not a credential.
			"redirect_uris":              []string{"https://rp.test.invalid/callback"},
			"jwks_uri":                   "https://rp.test.invalid/jwks.json",
			"token_endpoint_auth_method": "private_key_jwt",
			member:                       alg,
		})
	}
	for _, member := range []string{"token_endpoint_auth_signing_alg", "request_object_signing_alg"} {
		if got := register(member, "RS256"); got.status != http.StatusBadRequest || got.body["error"] != "invalid_client_metadata" {
			t.Errorf("POST /register %s=RS256: status=%d body=%s, want 400 invalid_client_metadata", member, got.status, got.raw)
		}
		if got := register(member, "PS256"); got.status != http.StatusCreated {
			t.Errorf("POST /register %s=PS256: status=%d body=%s, want 201", member, got.status, got.raw)
		}
	}
}
