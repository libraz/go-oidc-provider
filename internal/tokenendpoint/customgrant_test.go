package tokenendpoint_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
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

// TestCustomGrant_ScopeAllowedClientsRejected verifies custom grants
// enforce the global op.Scope.AllowedClients gate after the handler
// returns a scope set. The handler's scope is in the client's registered
// set, but the OP-level scope registry restricts it to another client.
func TestCustomGrant_ScopeAllowedClientsRejected(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:allowlist"
	handler := &recordingGrant{
		name: grantURN,
		response: op.CustomGrantResponse{
			AccessToken: "at",
			Scope:       []string{"billing:write"},
		},
	}
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithScope(op.Scope{
				Name:           "billing:write",
				Public:         true,
				AllowedClients: []string{"svc-billing"},
			}),
			op.WithCustomGrant(handler),
		),
	)
	f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/token", clock: clock}

	client, secret := customGrantClient(t, prov, grantURN, []string{"billing:write"}, nil)

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

// TestCustomGrant_BoundAccessToken_PlainBearer mints a JWT access
// token through the OP-side BoundAccessToken path on a plain
// confidential client (no DPoP, no mTLS). The wire token MUST parse
// against the OP's signing key, carry the standard RFC 9068 claims
// the OP fills, AND lack any cnf claim because the request was not
// sender-constrained.
func TestCustomGrant_BoundAccessToken_PlainBearer(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:bound-bearer"
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	handler := &recordingGrant{
		name: grantURN,
		response: op.CustomGrantResponse{
			BoundAccessToken: &op.BoundAccessToken{
				Subject: op.Subject("user-bound-1"),
				TTL:     2 * time.Minute,
				ExtraClaims: map[string]any{
					"tenant": "acme",
				},
			},
			Scope: []string{"read"},
		},
	}
	prov := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithCustomGrant(handler)),
	)
	f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/token", clock: clock}

	client, secret := customGrantClient(t, prov, grantURN, []string{"read"}, nil)

	form := url.Values{"grant_type": []string{grantURN}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["token_type"]; got != "Bearer" {
		t.Errorf("token_type=%v want Bearer", got)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	keySet := mustKeySet(t, prov)
	v := &tokens.AccessTokenVerifier{Keys: keySet, Issuer: prov.Issuer, Clock: clock}
	parsed, _, err := v.Verify(at)
	if err != nil {
		t.Fatalf("Verify access token: %v", err)
	}
	if parsed.Subject != "user-bound-1" {
		t.Errorf("sub=%q want user-bound-1", parsed.Subject)
	}
	if len(parsed.Audience) != 1 || parsed.Audience[0] != client.ID {
		t.Errorf("aud=%v want [%s]", parsed.Audience, client.ID)
	}
	if parsed.ClientID != client.ID {
		t.Errorf("client_id=%q want %q", parsed.ClientID, client.ID)
	}
	if parsed.JTI == "" {
		t.Error("jti missing on bound access token")
	}
	if parsed.GrantID == "" {
		t.Error("gid missing on bound access token")
	}
	if len(parsed.Confirmation) != 0 {
		t.Errorf("cnf must be absent on plain bearer bound token: %v", parsed.Confirmation)
	}
	rawClaims := decodeJWTPayload(t, at)
	if got := rawClaims["tenant"]; got != "acme" {
		t.Errorf("extra claim tenant=%v want acme", got)
	}
}

// decodeJWTPayload base64url-decodes the second segment of a compact-
// serialised JWT and returns it as a JSON object. The helper only
// inspects the payload — the access-token verifier above is the
// authoritative signature check — so this is just an extra-claim
// readback for tests that need to assert a claim the typed verifier
// does not project (e.g. handler-supplied extras on a BoundAccessToken).
func decodeJWTPayload(tb testing.TB, jwt string) map[string]any {
	tb.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		tb.Fatalf("decodeJWTPayload: expected 3 segments, got %d", len(parts))
	}
	raw, err := decodeBase64URL(parts[1])
	if err != nil {
		tb.Fatalf("decodeJWTPayload: base64url: %v", err)
	}
	out := map[string]any{}
	if err := jsonUnmarshal(raw, &out); err != nil {
		tb.Fatalf("decodeJWTPayload: json: %v", err)
	}
	return out
}

// TestCustomGrant_BoundAccessToken_DPoP drives a DPoP-bound request
// through the BoundAccessToken path and verifies the OP stamps cnf.jkt
// matching the proof's thumbprint without the handler having to
// re-implement DPoP binding logic.
func TestCustomGrant_BoundAccessToken_DPoP(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:bound-dpop"
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	handler := &recordingGrant{
		name: grantURN,
		response: op.CustomGrantResponse{
			BoundAccessToken: &op.BoundAccessToken{
				Subject: op.Subject("user-bound-dpop"),
				TTL:     2 * time.Minute,
			},
			Scope: []string{"read"},
		},
	}
	prov := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithFeature(feature.DPoP),
			op.WithCustomGrant(handler),
		),
	)
	f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/token", clock: clock}

	client, secret := customGrantClient(t, prov, grantURN, []string{"read"}, nil)

	key := newDPoPKey(t)
	form := url.Values{"grant_type": []string{grantURN}}
	proof := makeDPoPProof(t, key, "POST", f.endpoint, clock.now, "jti-cg-dpop-1", "")
	resp := postWithDPoP(t, prov.HTTPClient(nil), f.endpoint, form, client.ID, secret, proof)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["token_type"]; got != "DPoP" {
		t.Errorf("token_type=%v want DPoP", got)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	keySet := mustKeySet(t, prov)
	v := &tokens.AccessTokenVerifier{Keys: keySet, Issuer: prov.Issuer, Clock: clock}
	parsed, _, err := v.Verify(at)
	if err != nil {
		t.Fatalf("Verify access token: %v", err)
	}
	if got := parsed.Confirmation["jkt"]; got != key.jkt {
		t.Errorf("cnf.jkt=%q want %q", got, key.jkt)
	}
	if _, has := parsed.Confirmation["x5t#S256"]; has {
		t.Errorf("cnf.x5t#S256 must NOT be present on DPoP-only request")
	}
}

// TestCustomGrant_BoundAccessToken_MTLS drives an mTLS-bound request
// through the BoundAccessToken path and verifies the OP stamps
// cnf.x5t#S256 matching the leaf-cert thumbprint.
func TestCustomGrant_BoundAccessToken_MTLS(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:bound-mtls"
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	handler := &recordingGrant{
		name: grantURN,
		response: op.CustomGrantResponse{
			BoundAccessToken: &op.BoundAccessToken{
				Subject: op.Subject("user-bound-mtls"),
				TTL:     2 * time.Minute,
			},
			Scope: []string{"read"},
		},
	}
	prov := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithFeature(feature.MTLS),
			op.WithCustomGrant(handler),
		),
	)

	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	client := prov.RegisterClient(t, testkit.ClientFixture{
		ID:                      "client-cg-mtls",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{grantURN},
		Scopes:                  []string{"read"},
	})

	cert := generateMTLSLeaf(t)
	form := url.Values{"grant_type": []string{grantURN}}
	resp := postWithMTLS(t, prov, form, client.ID, secret, cert)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeMTLSResp(t, resp))
	}
	body := decodeMTLSResp(t, resp)
	if got := body["token_type"]; got != "Bearer" {
		// RFC 8705 keeps the bearer wire token_type; the binding
		// rides on cnf.x5t#S256.
		t.Errorf("token_type=%v want Bearer (mTLS keeps bearer wire type)", got)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("access_token missing")
	}
	keySet := mustKeySet(t, prov)
	v := &tokens.AccessTokenVerifier{Keys: keySet, Issuer: prov.Issuer, Clock: clock}
	parsed, _, err := v.Verify(at)
	if err != nil {
		t.Fatalf("Verify access token: %v", err)
	}
	want := mtls.Thumbprint(cert)
	if got := parsed.Confirmation["x5t#S256"]; got != want {
		t.Errorf("cnf.x5t#S256=%q want %q", got, want)
	}
	if _, has := parsed.Confirmation["jkt"]; has {
		t.Errorf("cnf.jkt must NOT be present on mTLS-only request")
	}
}

// TestCustomGrant_BoundAccessToken_ConflictReturns500 confirms a
// handler that returns BOTH AccessToken and BoundAccessToken trips
// the dispatcher's mutually-exclusive guard, surfacing as
// server_error on the wire (with no description leaking the
// dispatcher's internal sentinel name).
func TestCustomGrant_BoundAccessToken_ConflictReturns500(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:bound-conflict"
	handler := &recordingGrant{
		name: grantURN,
		response: op.CustomGrantResponse{
			AccessToken:      "handler-signed-at",
			BoundAccessToken: &op.BoundAccessToken{Subject: op.Subject("user-x")},
			Scope:            []string{"read"},
		},
	}
	prov := testkit.NewProvider(t, testkit.WithOptions(op.WithCustomGrant(handler)))
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
}

// TestCustomGrant_RefreshTokenIssuedWhenClientPermits confirms a
// handler that sets [op.CustomGrantResponse.IssueRefreshToken] causes
// the OP to mint and return an OP-owned refresh token when the client
// is registered for the refresh_token grant. The OP — not the handler —
// generates and persists the value through its own
// [store.RefreshTokenStore], so the credential rides the standard
// rotation / replay-cascade lineage (RFC 6749 §6).
func TestCustomGrant_RefreshTokenIssuedWhenClientPermits(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:refresh-issued"
	handler := &recordingGrant{
		name: grantURN,
		response: op.CustomGrantResponse{
			AccessToken:       "test-access-token",
			IssueRefreshToken: true,
			Subject:           op.Subject("user-123"),
			Scope:             []string{"read"},
		},
	}
	prov := testkit.NewProvider(t, testkit.WithOptions(op.WithCustomGrant(handler)))
	f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/token"}

	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	client := prov.RegisterClient(t, testkit.ClientFixture{
		ID:                      "client-cg-refresh",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{grantURN, "refresh_token"},
		Scopes:                  []string{"read"},
	})

	form := url.Values{"grant_type": []string{grantURN}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if rt, _ := body["refresh_token"].(string); rt == "" {
		t.Errorf("refresh_token missing; want an OP-minted value")
	}
}

// TestCustomGrant_RefreshTokenDroppedWhenClientNotRegistered confirms the
// OP gate drops the refresh token — without failing the response — when
// the client is not registered for the refresh_token grant. The request
// is honoured (200) with the refresh token silently omitted and a
// custom_grant.refresh_dropped audit event (RFC 6749 §6).
func TestCustomGrant_RefreshTokenDroppedWhenClientNotRegistered(t *testing.T) {
	t.Parallel()

	const grantURN = "urn:example:grant-type:refresh-dropped"
	handler := &recordingGrant{
		name: grantURN,
		response: op.CustomGrantResponse{
			AccessToken:       "test-access-token",
			IssueRefreshToken: true,
			Scope:             []string{"read"},
		},
	}
	prov := testkit.NewProvider(t, testkit.WithOptions(op.WithCustomGrant(handler)))
	f := &fixture{prov: prov, endpoint: prov.Server.URL + "/oidc/token"}

	client, secret := customGrantClient(t, prov, grantURN, []string{"read"}, nil)

	form := url.Values{"grant_type": []string{grantURN}}
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if rt, _ := body["refresh_token"].(string); rt != "" {
		t.Errorf("refresh_token=%q; want dropped (client not registered for refresh_token)", rt)
	}
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
