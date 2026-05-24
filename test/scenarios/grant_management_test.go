package scenarios_test

// Catalog: test/scenarios/catalog/grant_management.yaml (GM-NNN)
// Spec: OAuth 2.0 Grant Management draft §3 / §5 / §6 / §7

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

const (
	gmClientID = "rp-gm"
	gmCallback = "https://rp.testkit.invalid/callback"
	gmSecret   = "rp-gm-secret" //nolint:gosec // test fixture: not a real credential.
)

type gmEnv struct {
	tk *testkit.Provider
}

func newGMEnv(t *testing.T, actionRequired bool) *gmEnv {
	t.Helper()
	hash, err := op.HashClientSecret(gmSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithFeature(feature.Introspect),
		op.WithGrantManagement([]op.GrantManagementAction{
			op.GrantActionCreate, op.GrantActionReplace, op.GrantActionMerge,
			op.GrantActionQuery, op.GrantActionRevoke,
		}, actionRequired),
	))
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      gmClientID,
		SecretHash:              hash,
		RedirectURIs:            []string{gmCallback},
		Scopes:                  []string{"openid", "profile", "email", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	return &gmEnv{tk: tk}
}

// authorizeGrant runs a code flow with the supplied grant_management_action
// (and optional grant_id / scope) and exchanges the code, returning the
// token response.
func (e *gmEnv) authorizeGrant(t *testing.T, action, grantID, scope string) scenariokit.TokenResponse {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	extra := url.Values{}
	if action != "" {
		extra.Set("grant_management_action", action)
	}
	if grantID != "" {
		extra.Set("grant_id", grantID)
	}
	flow := scenariokit.RunCodeFlow(t, e.tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    gmClientID,
		RedirectURI: gmCallback,
		Scope:       scope,
		PKCE:        pkce,
		Extra:       extra,
	})
	if flow.Code == "" {
		t.Fatalf("authorize (action=%s) failed: %+v", action, flow)
	}
	return scenariokit.ExchangeCode(t, e.tk, scenariokit.ExchangeCodeRequest{
		Code: flow.Code, RedirectURI: gmCallback, Verifier: pkce.Verifier,
		ClientID: gmClientID, ClientSecret: gmSecret,
	})
}

// endpoint issues a method request to the grant management endpoint for
// grantID with the given client's Basic credentials, returning status +
// decoded JSON body.
func (e *gmEnv) endpoint(t *testing.T, method, grantID, clientID, secret string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), method,
		e.tk.Server.URL+"/oidc/grant_management/"+grantID, http.NoBody)
	if err != nil {
		t.Fatalf("build %s grant_management: %v", method, err)
	}
	req.SetBasicAuth(clientID, secret)
	resp, err := e.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("%s grant_management: %v", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := map[string]any{}
	if resp.StatusCode == http.StatusOK {
		body = decodeJSONBody(t, resp)
	}
	return resp.StatusCode, body
}

func TestScenario_GM_001_CreateReturnsGrantID(t *testing.T) {
	t.Parallel()
	env := newGMEnv(t, false)
	tok := env.authorizeGrant(t, "create", "", "openid profile")
	if gid, _ := tok.Raw["grant_id"].(string); gid == "" {
		t.Fatalf("token response missing grant_id: %v", tok.Raw)
	}
}

func TestScenario_GM_002_GrantIDScopedToOwningClient(t *testing.T) {
	t.Parallel()
	env := newGMEnv(t, false)
	// Seed a second confidential client that will attempt to reach the
	// first client's grant.
	hash, err := op.HashClientSecret("other-secret")
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	env.tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-gm-other",
		SecretHash:              hash,
		RedirectURIs:            []string{gmCallback},
		Scopes:                  []string{"openid", "profile"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	tok := env.authorizeGrant(t, "create", "", "openid profile")
	grantID, _ := tok.Raw["grant_id"].(string)
	if grantID == "" {
		t.Fatal("no grant_id from create")
	}

	// The foreign client must not query or revoke the grant.
	if status, _ := env.endpoint(t, http.MethodGet, grantID, "rp-gm-other", "other-secret"); status != http.StatusNotFound {
		t.Errorf("foreign GET status=%d want 404", status)
	}
	if status, _ := env.endpoint(t, http.MethodDelete, grantID, "rp-gm-other", "other-secret"); status != http.StatusNotFound {
		t.Errorf("foreign DELETE status=%d want 404", status)
	}
	// The owner can still query it: the grant was left intact.
	if status, _ := env.endpoint(t, http.MethodGet, grantID, gmClientID, gmSecret); status != http.StatusOK {
		t.Errorf("owner GET after foreign attempts status=%d want 200", status)
	}
}

func TestScenario_GM_003_ReplaceOverwritesScope(t *testing.T) {
	t.Parallel()
	env := newGMEnv(t, false)
	created := env.authorizeGrant(t, "create", "", "openid profile email")
	grantID, _ := created.Raw["grant_id"].(string)
	if grantID == "" {
		t.Fatal("no grant_id from create")
	}
	env.authorizeGrant(t, "replace", grantID, "openid profile")

	status, body := env.endpoint(t, http.MethodGet, grantID, gmClientID, gmSecret)
	if status != http.StatusOK {
		t.Fatalf("query status=%d", status)
	}
	scope := gmQueryScope(t, body)
	if strings.Contains(scope, "email") {
		t.Errorf("replace did not drop email: scope=%q", scope)
	}
	if !strings.Contains(scope, "openid") || !strings.Contains(scope, "profile") {
		t.Errorf("replace lost expected scopes: scope=%q", scope)
	}
}

func TestScenario_GM_004_MergeUnionsScope(t *testing.T) {
	t.Parallel()
	env := newGMEnv(t, false)
	created := env.authorizeGrant(t, "create", "", "openid profile")
	grantID, _ := created.Raw["grant_id"].(string)
	if grantID == "" {
		t.Fatal("no grant_id from create")
	}
	env.authorizeGrant(t, "merge", grantID, "openid email")

	status, body := env.endpoint(t, http.MethodGet, grantID, gmClientID, gmSecret)
	if status != http.StatusOK {
		t.Fatalf("query status=%d", status)
	}
	scope := gmQueryScope(t, body)
	for _, want := range []string{"openid", "profile", "email"} {
		if !strings.Contains(scope, want) {
			t.Errorf("merge missing %q: scope=%q", want, scope)
		}
	}
}

func TestScenario_GM_005_QueryReturnsGrant(t *testing.T) {
	t.Parallel()
	env := newGMEnv(t, false)
	tok := env.authorizeGrant(t, "create", "", "openid profile")
	grantID, _ := tok.Raw["grant_id"].(string)
	if grantID == "" {
		t.Fatal("no grant_id from create")
	}
	status, body := env.endpoint(t, http.MethodGet, grantID, gmClientID, gmSecret)
	if status != http.StatusOK {
		t.Fatalf("query status=%d body=%v", status, body)
	}
	if scope := gmQueryScope(t, body); !strings.Contains(scope, "openid") {
		t.Errorf("query scope=%q missing openid", scope)
	}
}

func TestScenario_GM_006_RevokeTearsDownGrant(t *testing.T) {
	t.Parallel()
	env := newGMEnv(t, false)
	tok := env.authorizeGrant(t, "create", "", "openid profile offline_access")
	grantID, _ := tok.Raw["grant_id"].(string)
	if grantID == "" {
		t.Fatal("no grant_id from create")
	}
	if tok.RefreshToken == "" {
		t.Fatal("offline_access requested but no refresh_token")
	}

	if status, _ := env.endpoint(t, http.MethodDelete, grantID, gmClientID, gmSecret); status != http.StatusNoContent {
		t.Fatalf("DELETE status=%d want 204", status)
	}
	// Query now reports the grant gone.
	if status, _ := env.endpoint(t, http.MethodGet, grantID, gmClientID, gmSecret); status != http.StatusNotFound {
		t.Errorf("post-revoke query status=%d want 404", status)
	}
	// The refresh token bound to the grant no longer works.
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		env.tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build refresh: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(gmClientID, gmSecret)
	resp, err := env.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("refresh after revoke: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		t.Errorf("refresh after revoke succeeded (status 200), want failure")
	}
}

func TestScenario_GM_007_ActionRequiredRejectsOmission(t *testing.T) {
	t.Parallel()
	env := newGMEnv(t, true)
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, env.tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    gmClientID,
		RedirectURI: gmCallback,
		Scope:       "openid profile",
		PKCE:        pkce,
	})
	if flow.Code != "" {
		t.Fatalf("expected rejection when grant_management_action omitted, got code: %+v", flow)
	}
	if flow.Error != "invalid_request" {
		t.Errorf("error=%q want invalid_request", flow.Error)
	}
}

// gmQueryScope extracts the space-delimited scope from a grant management
// query response (scopes is an array of {scope} objects).
func gmQueryScope(t *testing.T, body map[string]any) string {
	t.Helper()
	scopes, ok := body["scopes"].([]any)
	if !ok || len(scopes) == 0 {
		t.Fatalf("query body missing scopes: %v", body)
	}
	first, _ := scopes[0].(map[string]any)
	s, _ := first["scope"].(string)
	return s
}
