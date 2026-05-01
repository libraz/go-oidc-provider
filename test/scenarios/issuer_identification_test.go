package scenarios_test

// Catalog: test/scenarios/catalog/issuer_identification.yaml (ISS-NNN)
// Spec:
//   - RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification
//   - RFC 8414 §2 — issuer metadata field
//   - OIDC Core 1.0 §3.1.2.5 / §3.1.2.6
//   - OIDC Core 1.0 §3.3 (hybrid)
//   - JARM §4.1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// TestScenario_ISS_001_DiscoveryAdvertisesIssParameterSupported checks
// that the OP, with issuer-identification enabled (the project
// default), advertises authorization_response_iss_parameter_supported
// = true in its discovery document.
//
// Spec: RFC 9207 §3 (the OP MUST publish this metadata field when it
// stamps `iss` on authorization responses).
func TestScenario_ISS_001_DiscoveryAdvertisesIssParameterSupported(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		p.Server.URL+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status=%d want 200", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	got, ok := doc["authorization_response_iss_parameter_supported"]
	if !ok {
		t.Fatal("authorization_response_iss_parameter_supported missing from discovery doc")
	}
	if v, _ := got.(bool); !v {
		t.Errorf("authorization_response_iss_parameter_supported=%v want true", got)
	}
}

// TestScenario_ISS_010_CodeFlowQueryCarriesIss checks that a successful
// response_type=code authorization redirect carries `code`, `state`,
// and `iss` as query parameters, and that the iss value matches the
// OP's issuer.
//
// Spec: RFC 9207 §2 (the OP that publishes
// authorization_response_iss_parameter_supported MUST stamp `iss` on
// every authorization response).
func TestScenario_ISS_010_CodeFlowQueryCarriesIss(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-iss-010"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-iss-010-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	if flow.State != scenariokit.DefaultState {
		t.Errorf("state=%q want %q", flow.State, scenariokit.DefaultState)
	}
	if flow.Iss == "" {
		t.Fatal("authorize callback missing iss query parameter")
	}
	if flow.Iss != tk.Issuer {
		t.Errorf("iss=%q want %q", flow.Iss, tk.Issuer)
	}
	if flow.Location == nil {
		t.Fatal("captured callback Location is nil")
	}
	if got := flow.Location.Query().Get("iss"); got == "" {
		t.Error("iss query parameter missing from raw redirect URL")
	}
	if flow.Location.RawFragment != "" || flow.Location.Fragment != "" {
		t.Errorf("response_type=code MUST use query encoding, got fragment=%q", flow.Location.Fragment)
	}
}

func TestScenario_ISS_011_CodeTokenFragmentCarriesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-011")
}

func TestScenario_ISS_012_CodeIDTokenFragmentEmbedsIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-012")
}

func TestScenario_ISS_013_CodeIDTokenTokenFragmentCarriesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-013")
}

func TestScenario_ISS_014_IDTokenTokenFragmentCarriesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-014")
}

func TestScenario_ISS_015_IDTokenFragmentCarriesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-015")
}

func TestScenario_ISS_016_NoneResponseTypeQueryCarriesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-016")
}

// TestScenario_ISS_017_JARMResponseEmbedsIssClaim checks that, with
// the JARM feature enabled, an authorize success delivered via
// response_mode=jwt carries the response JWT in the redirect's query
// string and embeds the OP's `iss` value as a claim inside the JWT
// payload (rather than as a bare query parameter).
//
// Spec: RFC 9207 §2 + JARM §4.1.
func TestScenario_ISS_017_JARMResponseEmbedsIssClaim(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-iss-017"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-iss-017-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.JARM)))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ResponseTypes:           []string{"code"},
		GrantTypes:              []string{"authorization_code"},
	})
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		PKCE:        pkce,
		Extra:       url.Values{"response_mode": {"jwt"}},
	})

	if flow.Error != "" {
		t.Fatalf("authorize error=%s desc=%s", flow.Error, flow.ErrorDesc)
	}
	if flow.Location == nil {
		t.Fatal("captured callback Location is nil")
	}
	if flow.Location.RawFragment != "" || flow.Location.Fragment != "" {
		t.Errorf("response_type=code with response_mode=jwt must resolve to query delivery; got fragment=%q in %s",
			flow.Location.Fragment, flow.Location.String())
	}
	if got := flow.Location.Query().Get("iss"); got != "" {
		t.Errorf("response_mode=jwt must not stamp a bare iss query parameter (iss travels inside the JWT); got %q", got)
	}

	rawJWT := flow.Location.Query().Get("response")
	if rawJWT == "" {
		t.Fatalf("'response' parameter missing from JARM callback: %s", flow.Location.String())
	}

	claims := decodeScenarioJWTClaims(t, rawJWT)
	iss, _ := claims["iss"].(string)
	if iss == "" {
		t.Fatalf("iss claim missing from JARM payload: %v", claims)
	}
	if iss != tk.Issuer {
		t.Errorf("iss=%q want %q", iss, tk.Issuer)
	}
}

// TestScenario_ISS_020_RegularErrorRedirectCarriesIss checks that a
// post-redirect-URI authorize error (here: a scope outside the
// client's registered set) redirects back with `error`, `state`, and
// `iss` as query parameters. RFC 9207 §2 requires the OP to stamp
// `iss` on every authorization response — including the error path
// (RFC 6749 §4.1.2.1).
//
// Spec: RFC 9207 §2 + RFC 6749 §4.1.2.1.
func TestScenario_ISS_020_RegularErrorRedirectCarriesIss(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-iss-020"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-iss-020-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		// "billing:write" is outside the client's registered scope set,
		// so the OP rejects with invalid_scope after redirect_uri has
		// been validated — exactly the post-redirect-URI error path
		// RFC 9207 §2 requires `iss` on.
		Scope: "openid billing:write",
		PKCE:  pkce,
	})
	if flow.Error != "invalid_scope" {
		t.Fatalf("error=%q want invalid_scope (flow=%+v)", flow.Error, flow)
	}
	if flow.State != scenariokit.DefaultState {
		t.Errorf("state=%q want %q", flow.State, scenariokit.DefaultState)
	}
	if flow.Iss == "" {
		t.Fatal("error redirect missing iss query parameter")
	}
	if flow.Iss != tk.Issuer {
		t.Errorf("iss=%q want %q", flow.Iss, tk.Issuer)
	}
	if flow.Location == nil {
		t.Fatal("captured callback Location is nil")
	}
	if flow.Location.Fragment != "" || flow.Location.RawFragment != "" {
		t.Errorf("response_type=code error redirect must not use fragment encoding, got fragment=%q",
			flow.Location.Fragment)
	}
	if flow.Location.RawQuery == "" {
		t.Error("error redirect must carry query parameters")
	}
}

func TestScenario_ISS_021_NoneResponseTypeErrorCarriesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-021")
}

// TestScenario_ISS_022_JARMErrorQueryCarriesIss checks that an
// authorize error on a response_mode=jwt request resolves to query
// delivery (because response_type=code is the only response_type the
// OP supports), the redirect carries a single "response" query
// parameter holding the JARM error JWT, and the JWT payload embeds
// iss / error / state. RFC 9207 §2 requires `iss` on every
// authorization response — JARM §4.1 dictates that under
// response_mode=jwt the iss travels as a claim inside the response
// JWT rather than as a bare query parameter.
//
// Spec: RFC 9207 §2 + JARM §4.1.
func TestScenario_ISS_022_JARMErrorQueryCarriesIss(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-iss-022"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-iss-022-secret"

	hash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}

	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithFeature(feature.JARM)))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      clientID,
		SecretHash:              hash,
		RedirectURIs:            []string{callback},
		Scopes:                  []string{"openid", "profile"},
		TokenEndpointAuthMethod: "client_secret_basic",
		ResponseTypes:           []string{"code"},
		GrantTypes:              []string{"authorization_code"},
	})

	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		// "billing:write" is outside the client's registered scope set,
		// so the OP rejects with invalid_scope after redirect_uri has
		// been validated — exactly the post-redirect-URI error path
		// RFC 9207 §2 requires `iss` on, and JARM §4.1 requires the
		// JWT envelope on.
		Scope: "openid billing:write",
		PKCE:  pkce,
		Extra: url.Values{"response_mode": {"jwt"}},
	})

	if flow.Location == nil {
		t.Fatal("captured callback Location is nil")
	}
	if flow.Location.RawFragment != "" || flow.Location.Fragment != "" {
		t.Errorf("response_type=code with response_mode=jwt must resolve to query delivery; got fragment=%q in %s",
			flow.Location.Fragment, flow.Location.String())
	}
	if got := flow.Location.Query().Get("iss"); got != "" {
		t.Errorf("response_mode=jwt must not stamp a bare iss query parameter (iss travels inside the JWT); got %q", got)
	}
	if got := flow.Location.Query().Get("error"); got != "" {
		t.Errorf("response_mode=jwt must not stamp a bare error query parameter (error travels inside the JWT); got %q", got)
	}

	rawJWT := flow.Location.Query().Get("response")
	if rawJWT == "" {
		t.Fatalf("'response' parameter missing from JARM error callback: %s", flow.Location.String())
	}

	claims := decodeScenarioJWTClaims(t, rawJWT)
	iss, _ := claims["iss"].(string)
	if iss == "" {
		t.Fatalf("iss claim missing from JARM error payload: %v", claims)
	}
	if iss != tk.Issuer {
		t.Errorf("iss=%q want %q", iss, tk.Issuer)
	}
	if got, _ := claims["error"].(string); got != "invalid_scope" {
		t.Errorf("error=%q want invalid_scope (claims=%v)", got, claims)
	}
	if got, _ := claims["state"].(string); got != scenariokit.DefaultState {
		t.Errorf("state=%q want %q", got, scenariokit.DefaultState)
	}
	if got := claims["aud"]; got != rp.ID {
		t.Errorf("aud=%v want %q", got, rp.ID)
	}
}

func TestScenario_ISS_023_JARMHybridErrorFragmentCarriesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-023")
}
