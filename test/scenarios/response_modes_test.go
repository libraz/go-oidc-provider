package scenarios_test

// Catalog: test/scenarios/catalog/response_modes.yaml (RMO-NNN)
// Spec:
//   - OAuth 2.0 Multiple Response Type Encoding Practices §2 (response_mode)
//   - OAuth 2.0 Form Post Response Mode (Final)
//   - OAuth 2.0 Web Message Response Mode (draft, deprecated)
//   - OIDC Core 1.0 §3.1.2 (response_mode default selection)
//   - RFC 9207 — Authorization Server Issuer Identification

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

func TestScenario_RMO_001_FormPostSuccessRendersSelfSubmittingForm(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-001")
}

func TestScenario_RMO_002_FormPostHTMLEscapesRedirectURI(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-002")
}

func TestScenario_RMO_003_FormPostErrorPathRendersForm(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-003")
}

func TestScenario_RMO_004_FormPostGetAndPostBehaveIdentically(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-004")
}

func TestScenario_RMO_010_WebMessageSuccessRendersHTMLEnvelope(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-010")
}

func TestScenario_RMO_011_WebMessageIncludesStandardFields(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-011")
}

func TestScenario_RMO_012_WebMessageRelayModeRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-012")
}

func TestScenario_RMO_013_WebMessageStripsFramingHeaders(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-013")
}

func TestScenario_RMO_014_WebMessageErrorRendersEnvelope(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-014")
}

func TestScenario_RMO_020_DiscoveryAdvertisesWebMessage(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-020")
}

func TestScenario_RMO_030_RegisterResponseModeHookExposed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-030")
}

func TestScenario_RMO_031_CustomModeInvokedForSuccess(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-031")
}

func TestScenario_RMO_032_CustomModeInvokedForError(t *testing.T) {
	t.Parallel()
	t.Skip("pending: RMO-032")
}

// TestScenario_RMO_033_UnknownResponseModeRejected verifies that an
// /authorize request whose response_mode is neither the default nor any
// of the response_modes_supported values is rejected with a redirect
// carrying error=unsupported_response_mode and the OP's wire-form
// description "response_mode is not supported".
//
// The redirect target is the registered redirect_uri (the OP only emits
// a redirect-form error after redirect_uri has been validated; that
// gate already passes here because client_id and redirect_uri are
// well-formed).
//
// Spec: OAuth 2.0 Multiple Response Type Encoding Practices §2
// (response_mode); RFC 6749 §4.1.2.1 (error response shape).
func TestScenario_RMO_033_UnknownResponseModeRejected(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-rmo-033"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-rmo-033-secret"

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
	params := scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: callback,
		PKCE:        pkce,
		Extra:       url.Values{"response_mode": {"unknown-mode"}},
	}
	authorizeURL := tk.Server.URL + "/oidc/auth?" + params.Values().Encode()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authorizeURL, http.NoBody)
	if err != nil {
		t.Fatalf("build /authorize request: %v", err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	want, err := url.Parse(callback)
	if err != nil {
		t.Fatalf("parse callback: %v", err)
	}
	if loc.Scheme != want.Scheme || loc.Host != want.Host || loc.Path != want.Path {
		t.Fatalf("redirect=%s does not target redirect_uri %s", loc.String(), callback)
	}
	q := loc.Query()
	if got := q.Get("error"); got != "unsupported_response_mode" {
		t.Errorf("error=%q want unsupported_response_mode", got)
	}
	if got := q.Get("error_description"); got != "response_mode is not supported" {
		t.Errorf("error_description=%q want %q", got, "response_mode is not supported")
	}
	if got := q.Get("state"); got != scenariokit.DefaultState {
		t.Errorf("state=%q want %q", got, scenariokit.DefaultState)
	}
}

// TestScenario_RMO_040_DefaultResponseModeSelection verifies the
// code-leg of OIDC Core §3.1.2 default response_mode selection: a
// successful response_type=code authorization with no response_mode in
// the request encodes the response in the redirect's query string, not
// the fragment.
//
// v1.0's discovery advertises only response_types_supported=["code"];
// the implicit half of the spec rule (id_token / token defaulting to
// fragment) is recorded in the catalog row's behaviour block as not
// reachable at the wire because the OP rejects those response_type
// values upstream.
//
// Spec: OIDC Core 1.0 §3.1.2 (response_mode default).
func TestScenario_RMO_040_DefaultResponseModeSelection(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-rmo-040"
		callback = "https://rp.testkit.invalid/callback"
	)
	//nolint:gosec // test fixture: not a real credential.
	const clientSecret = "rp-rmo-040-secret"

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
		// Intentionally omit response_mode so the OP must apply the
		// default-selection rule from OIDC Core §3.1.2.
	})
	if flow.Error != "" {
		t.Fatalf("authorize error=%s desc=%s", flow.Error, flow.ErrorDesc)
	}
	if flow.Code == "" {
		t.Fatal("authorize callback missing code")
	}
	if flow.Location == nil {
		t.Fatal("captured callback Location is nil")
	}
	if flow.Location.RawFragment != "" || flow.Location.Fragment != "" {
		t.Errorf("response_type=code with no response_mode must default to query encoding; got fragment=%q in %s",
			flow.Location.Fragment, flow.Location.String())
	}
	// Spot-check that the canonical fields ride in the query string.
	q := flow.Location.Query()
	if got := q.Get("code"); got == "" {
		t.Error("code query parameter missing from default-mode redirect")
	}
	if got := q.Get("state"); got != scenariokit.DefaultState {
		t.Errorf("state=%q want %q", got, scenariokit.DefaultState)
	}
}
