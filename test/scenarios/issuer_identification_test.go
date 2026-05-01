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
	"testing"

	"github.com/libraz/go-oidc-provider/op"
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

func TestScenario_ISS_017_JARMResponseEmbedsIssClaim(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-017")
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

func TestScenario_ISS_022_JARMErrorQueryCarriesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-022")
}

func TestScenario_ISS_023_JARMHybridErrorFragmentCarriesIss(t *testing.T) {
	t.Parallel()
	t.Skip("pending: ISS-023")
}
