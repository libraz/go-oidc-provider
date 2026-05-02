package tokenendpoint_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// recordingGrant is a CustomGrantHandler whose Handle method returns a
// caller-supplied response and records the request that drove it. The
// type is the integration-test analog of the in-package stubHandler;
// the public op.CustomGrantHandler surface is exercised here so the
// adapter, dispatcher, and token endpoint wiring all run together.
type recordingGrant struct {
	name     string
	policy   op.ParamPolicy
	response op.CustomGrantResponse
	err      error
	gotReq   op.CustomGrantRequest
}

func (g *recordingGrant) Name() string                { return g.name }
func (g *recordingGrant) ParamPolicy() op.ParamPolicy { return g.policy }
func (g *recordingGrant) Handle(_ context.Context, req op.CustomGrantRequest) (op.CustomGrantResponse, error) {
	g.gotReq = req
	if g.err != nil {
		return op.CustomGrantResponse{}, g.err
	}
	return g.response, nil
}

// customGrantClient seeds a confidential client whose GrantTypes allow
// the supplied URN. Returns the client record and its plaintext secret
// so the test can drive Basic auth.
func customGrantClient(t *testing.T, prov *testkit.Provider, grantURN string, scopes, resources []string) (*store.Client, string) {
	t.Helper()
	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	client := prov.RegisterClient(t, testkit.ClientFixture{
		ID:                      "client-cg",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{grantURN},
		Scopes:                  scopes,
		Resources:               resources,
	})
	return client, secret
}

// TestCustomGrant_HappyPath exercises the full op.WithCustomGrant →
// dispatcher → token endpoint pipeline. The handler's response shape
// is reproduced verbatim on the wire (modulo the ttl seconds rounding
// the success envelope applies).
func TestCustomGrant_HappyPath(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:happy"
	handler := &recordingGrant{
		name:   grantURN,
		policy: op.ParamPolicy{Allowed: []string{"resource"}},
		response: op.CustomGrantResponse{
			AccessToken:    "test-access-token",
			AccessTokenTTL: 5 * 60_000_000_000, // 5 minutes in nanoseconds
			Scope:          []string{"read"},
			Audience:       []string{"https://api.example.com"},
		},
	}
	prov := testkit.NewProvider(t, testkit.WithOptions(op.WithCustomGrant(handler)))
	f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/token"}

	client, secret := customGrantClient(t, prov, grantURN,
		[]string{"read", "write"},
		[]string{"https://api.example.com"})

	form := url.Values{
		"grant_type": []string{grantURN},
		"resource":   []string{"https://api.example.com"},
	}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["access_token"]; got != "test-access-token" {
		t.Errorf("access_token=%v want test-access-token", got)
	}
	if got := body["token_type"]; got != "Bearer" {
		t.Errorf("token_type=%v want Bearer", got)
	}
	if got := body["scope"]; got != "read" {
		t.Errorf("scope=%v want read", got)
	}
	if handler.gotReq.Client == nil || handler.gotReq.Client.ID != client.ID {
		t.Errorf("handler did not receive client (got=%+v)", handler.gotReq.Client)
	}
	if got := handler.gotReq.Form["resource"]; len(got) != 1 || got[0] != "https://api.example.com" {
		t.Errorf("handler.Form[resource]=%v want [https://api.example.com]", got)
	}
}

// TestCustomGrant_UnknownGrantTypeReturns400 confirms that a
// grant_type which matches no registered handler hits the existing
// unsupported_grant_type branch unchanged. The test ensures the
// dispatcher does not silently swallow unknown grant_types when no
// handler is registered.
func TestCustomGrant_UnknownGrantTypeReturns400(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:registered"
	handler := &recordingGrant{name: grantURN, response: op.CustomGrantResponse{AccessToken: "x"}}
	prov := testkit.NewProvider(t, testkit.WithOptions(op.WithCustomGrant(handler)))
	f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/token"}

	client, secret := customGrantClient(t, prov, grantURN, []string{"read"}, nil)

	form := url.Values{"grant_type": []string{"urn:example:grant-type:nope"}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	if got := decodeJSON(t, resp)["error"]; got != "unsupported_grant_type" {
		t.Errorf("error=%v want unsupported_grant_type", got)
	}
}

// TestCustomGrant_ClientGrantNotPermitted confirms a client whose
// GrantTypes does not list the URN is rejected with
// unauthorized_client even when a handler is registered.
func TestCustomGrant_ClientGrantNotPermitted(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:perm"
	handler := &recordingGrant{name: grantURN, response: op.CustomGrantResponse{AccessToken: "x"}}
	prov := testkit.NewProvider(t, testkit.WithOptions(op.WithCustomGrant(handler)))
	f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/token"}

	client, secret := customGrantClient(t, prov, "authorization_code", nil, nil)

	form := url.Values{"grant_type": []string{grantURN}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	if got := decodeJSON(t, resp)["error"]; got != "unauthorized_client" {
		t.Errorf("error=%v want unauthorized_client", got)
	}
}

// TestCustomGrant_ScopeInflationReturns400 confirms a handler whose
// response scope exceeds the client's registered set is rejected with
// invalid_scope.
func TestCustomGrant_ScopeInflationReturns400(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:scope"
	handler := &recordingGrant{
		name: grantURN,
		response: op.CustomGrantResponse{
			AccessToken: "at",
			Scope:       []string{"read", "admin"}, // admin not in client's set
		},
	}
	prov := testkit.NewProvider(t, testkit.WithOptions(op.WithCustomGrant(handler)))
	f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/token"}

	client, secret := customGrantClient(t, prov, grantURN, []string{"read", "write"}, nil)

	form := url.Values{"grant_type": []string{grantURN}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	if got := decodeJSON(t, resp)["error"]; got != "invalid_scope" {
		t.Errorf("error=%v want invalid_scope", got)
	}
}

// TestCustomGrant_HandlerPanicReturns500 confirms that a panic in the
// handler is converted to server_error without leaking the panic
// message into the wire response.
func TestCustomGrant_HandlerPanicReturns500(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:panic"
	prov := testkit.NewProvider(t, testkit.WithOptions(op.WithCustomGrant(&panicGrant{name: grantURN})))
	f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/token"}

	client, secret := customGrantClient(t, prov, grantURN, []string{"read"}, nil)

	form := url.Values{"grant_type": []string{grantURN}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if got := body["error"]; got != "server_error" {
		t.Errorf("error=%v want server_error", got)
	}
	if desc, _ := body["error_description"].(string); desc != "" {
		t.Errorf("error_description=%q want empty (panic must not leak)", desc)
	}
}

type panicGrant struct{ name string }

func (g *panicGrant) Name() string                { return g.name }
func (g *panicGrant) ParamPolicy() op.ParamPolicy { return op.ParamPolicy{} }
func (g *panicGrant) Handle(_ context.Context, _ op.CustomGrantRequest) (op.CustomGrantResponse, error) {
	panic("intentional panic for test")
}

// TestCustomGrant_TTLCappedToGlobal confirms a handler-supplied TTL
// above the global access-token cap is truncated to the cap before
// the wire response is written.
func TestCustomGrant_TTLCappedToGlobal(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:ttl"
	handler := &recordingGrant{
		name: grantURN,
		response: op.CustomGrantResponse{
			AccessToken:    "at",
			AccessTokenTTL: 24 * 60 * 60_000_000_000, // 24 hours
		},
	}
	// Default global cap is op.DefaultAccessTokenTTL (5 minutes); the
	// dispatcher truncates to it.
	prov := testkit.NewProvider(t, testkit.WithOptions(op.WithCustomGrant(handler)))
	f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/token"}

	client, secret := customGrantClient(t, prov, grantURN, []string{"read"}, nil)

	form := url.Values{"grant_type": []string{grantURN}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	expires, ok := body["expires_in"].(float64)
	if !ok {
		t.Fatalf("expires_in not a number: %T", body["expires_in"])
	}
	// The default cap (5 min = 300s) is what the dispatcher truncates to.
	if expires != 300 {
		t.Errorf("expires_in=%v want 300 (capped to default 5m)", expires)
	}
}
