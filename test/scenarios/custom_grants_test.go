package scenarios_test

// Catalog: test/scenarios/catalog/custom_grants.yaml (CG-NNN)
// Spec:
//   - RFC 6749 §4.5 — Extension Grants
//   - RFC 6749 §3.2 — Token Endpoint
//   - RFC 6749 §5.2 — Error Response
//   - RFC 8693 — OAuth 2.0 Token Exchange (informative)

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// cgClientSecret is the deterministic confidential-client secret the
// CG-suite reuses across rows. The catalogue requires fixed fixtures
// (no randomness) so a failure trace can be replayed without seeding.
const cgClientSecret = "cg-client-secret"

// recordingCustomGrant captures the request the dispatcher hands the
// handler so the test can pin the parsed-form shape, and replies with
// a fixed response body so the test can pin the wire envelope.
type recordingCustomGrant struct {
	name     string
	policy   op.ParamPolicy
	response op.CustomGrantResponse

	mu      sync.Mutex
	gotForm map[string][]string
	gotKid  string
}

func (g *recordingCustomGrant) Name() string                { return g.name }
func (g *recordingCustomGrant) ParamPolicy() op.ParamPolicy { return g.policy }
func (g *recordingCustomGrant) Handle(_ context.Context, req op.CustomGrantRequest) (op.CustomGrantResponse, error) {
	g.mu.Lock()
	g.gotForm = cloneFormValues(req.Form)
	if req.Client != nil {
		g.gotKid = req.Client.ID
	}
	g.mu.Unlock()
	return g.response, nil
}

func cloneFormValues(in map[string][]string) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for k, v := range in {
		out[k] = slices.Clone(v)
	}
	return out
}

// newCGProvider builds a testkit.Provider that wires the supplied
// custom-grant handler and a confidential client whose GrantTypes
// allow it. The function is the per-row analog of newOpaqueProvider /
// newJARProvider patterns in this suite.
func newCGProvider(t *testing.T, handler op.CustomGrantHandler, scopes, resources []string) (*testkit.Provider, *store.Client) {
	t.Helper()
	hash, err := op.HashClientSecret(cgClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithCustomGrant(handler)))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "cg-rp",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{handler.Name()},
		Scopes:                  scopes,
		Resources:               resources,
	})
	return tk, rp
}

// postCustomGrant submits a token-endpoint request with HTTP Basic
// auth and returns the (status, decoded body) pair. The helper parses
// the wire body once so each row asserts on the JSON shape directly.
func postCustomGrant(t *testing.T, tk *testkit.Provider, form url.Values, clientID, secret string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /oidc/token: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var decoded map[string]any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatalf("unmarshal body=%q: %v", body, err)
		}
	}
	return resp.StatusCode, decoded
}

// TestScenario_CG_001_RegisterGrantTypeAddsToRegistry confirms that a
// grant_type registered through op.WithCustomGrant appears in the
// /.well-known/openid-configuration grant_types_supported field. The
// row is the registration-side counterpart to CG-008's invocation
// path.
//
// Spec: RFC 6749 §4.5 / RFC 8414 §2.
func TestScenario_CG_001_RegisterGrantTypeAddsToRegistry(t *testing.T) {
	t.Parallel()
	const grantURN = "urn:example:grant-type:cg-001"
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithCustomGrant(&recordingCustomGrant{name: grantURN}),
	))
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	raw, ok := doc["grant_types_supported"].([]any)
	if !ok {
		t.Fatalf("grant_types_supported not an array: %T (%v)",
			doc["grant_types_supported"], doc["grant_types_supported"])
	}
	for _, v := range raw {
		if s, _ := v.(string); s == grantURN {
			return
		}
	}
	t.Fatalf("grant_types_supported does not contain %q (got %v)", grantURN, raw)
}

// TestScenario_CG_002_RegisterGrantTypeWithoutParamNames confirms that
// op.WithCustomGrant accepts a handler whose ParamPolicy is the zero
// value (no Allowed list). The dispatcher then admits only the
// implicit shared parameters (grant_type / client_id / ...).
//
// Spec: RFC 6749 §4.5 (extension grants — no per-grant parameter
// requirement).
func TestScenario_CG_002_RegisterGrantTypeWithoutParamNames(t *testing.T) {
	t.Parallel()
	const grantURN = "urn:example:grant-type:cg-002"
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithCustomGrant(&recordingCustomGrant{
			name:     grantURN,
			response: op.CustomGrantResponse{AccessToken: "ok-002"},
		}),
	))
	if tk.Server == nil {
		t.Fatal("provider server is nil")
	}
}

// TestScenario_CG_003_RegisterGrantTypeAcceptsNullOrString confirms a
// handler with a single-element Allowed list (the moral equivalent of
// the upstream "null OR single-string" admission rule) is accepted.
//
// Spec: RFC 6749 §4.5.
func TestScenario_CG_003_RegisterGrantTypeAcceptsNullOrString(t *testing.T) {
	t.Parallel()
	const grantURN = "urn:example:grant-type:cg-003"
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithCustomGrant(&recordingCustomGrant{
			name:     grantURN,
			policy:   op.ParamPolicy{Allowed: []string{"resource"}},
			response: op.CustomGrantResponse{AccessToken: "ok-003"},
		}),
	))
	if tk.Server == nil {
		t.Fatal("provider server is nil")
	}
}

// TestScenario_CG_004_DuplicateParameterRejectedByDefault confirms a
// duplicated handler-allowed parameter (NOT in DupesAllowed) yields
// 400 invalid_request. The dispatcher's wire envelope follows
// RFC 6749 §5.2 — the failure description is sanitised to the failure
// family (the per-parameter detail rides on the audit emission).
//
// Spec: RFC 6749 §3.2 (parameters MUST NOT be duplicated).
func TestScenario_CG_004_DuplicateParameterRejectedByDefault(t *testing.T) {
	t.Parallel()
	const grantURN = "urn:example:grant-type:cg-004"
	handler := &recordingCustomGrant{
		name:     grantURN,
		policy:   op.ParamPolicy{Allowed: []string{"name"}},
		response: op.CustomGrantResponse{AccessToken: "ok-004"},
	}
	tk, rp := newCGProvider(t, handler, []string{"openid"}, nil)
	form := url.Values{
		"grant_type": []string{grantURN},
		"name":       []string{"John", "FooBar"},
	}
	status, body := postCustomGrant(t, tk, form, rp.ID, cgClientSecret)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", status, body)
	}
	if got := body["error"]; got != "invalid_request" {
		t.Errorf("error=%v want invalid_request", got)
	}
}

// TestScenario_CG_005_WhitelistedParameterMayRepeat confirms a
// parameter listed under DupesAllowed is delivered to the handler as
// an ordered slice of all submitted values.
//
// Spec: RFC 6749 §3.2 / RFC 8693 §2 (resource as a repeatable
// parameter, informative).
func TestScenario_CG_005_WhitelistedParameterMayRepeat(t *testing.T) {
	t.Parallel()
	const grantURN = "urn:example:grant-type:cg-005"
	handler := &recordingCustomGrant{
		name: grantURN,
		policy: op.ParamPolicy{
			Allowed:      []string{"resource"},
			DupesAllowed: []string{"resource"},
		},
		response: op.CustomGrantResponse{AccessToken: "ok-005"},
	}
	tk, rp := newCGProvider(t, handler, []string{"openid"}, nil)
	form := url.Values{
		"grant_type": []string{grantURN},
		"resource":   []string{"https://api.first.example/", "https://api.second.example/"},
	}
	status, body := postCustomGrant(t, tk, form, rp.ID, cgClientSecret)
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", status, body)
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	got := handler.gotForm["resource"]
	want := []string{"https://api.first.example/", "https://api.second.example/"}
	if !slices.Equal(got, want) {
		t.Errorf("handler.Form[resource]=%v want %v (order preserved)", got, want)
	}
}

// TestScenario_CG_006_PartialExemptionStillRejectsOthers confirms that
// when a handler exempts only one of two declared parameters, the
// non-exempt parameter is still subject to the duplicate-rejection
// rule — duplicating it yields 400 invalid_request even though the
// other parameter freely repeats.
//
// Spec: RFC 6749 §3.2.
func TestScenario_CG_006_PartialExemptionStillRejectsOthers(t *testing.T) {
	t.Parallel()
	const grantURN = "urn:example:grant-type:cg-006"
	handler := &recordingCustomGrant{
		name: grantURN,
		policy: op.ParamPolicy{
			Allowed:      []string{"audience", "name"},
			DupesAllowed: []string{"audience"},
		},
		response: op.CustomGrantResponse{AccessToken: "ok-006"},
	}
	tk, rp := newCGProvider(t, handler, []string{"openid"}, nil)
	form := url.Values{
		"grant_type": []string{grantURN},
		"audience":   []string{"https://api.example/"},
		"name":       []string{"a", "b"},
	}
	status, body := postCustomGrant(t, tk, form, rp.ID, cgClientSecret)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", status, body)
	}
	if got := body["error"]; got != "invalid_request" {
		t.Errorf("error=%v want invalid_request", got)
	}
}

// TestScenario_CG_007_GrantTypeCannotBeExempted confirms the OP
// refuses to register a custom grant whose ParamPolicy.DupesAllowed
// names "grant_type". The protection lives at registration time
// (op.WithCustomGrant returns ErrCustomGrantSecretLikeExempt) so a
// misconfigured handler cannot reach the dispatcher in the first
// place — the security guarantee the row requires.
//
// Spec: RFC 6749 §3.2 (grant_type is a security-sensitive parameter
// and cannot be exempted from the duplication rule).
func TestScenario_CG_007_GrantTypeCannotBeExempted(t *testing.T) {
	t.Parallel()
	handler := &recordingCustomGrant{
		name: "urn:example:grant-type:cg-007",
		policy: op.ParamPolicy{
			Allowed:      []string{"grant_type"},
			DupesAllowed: []string{"grant_type"},
		},
	}
	_, err := op.New(testkit.MinimalOptions(t, op.WithCustomGrant(handler))...)
	if !errors.Is(err, op.ErrCustomGrantSecretLikeExempt) {
		t.Fatalf("op.New err = %v, want %v", err, op.ErrCustomGrantSecretLikeExempt)
	}
}

// TestScenario_CG_008_ClientOptInExecutesHandler confirms that a
// client whose registered grant_types includes the custom URN can
// invoke it: the handler runs and the wire envelope mirrors the
// access_token / token_type / expires_in shape RFC 6749 §5.1
// requires.
//
// Spec: RFC 6749 §4.5 / RFC 7591 §2 (client metadata advertises the
// allowed grant types).
func TestScenario_CG_008_ClientOptInExecutesHandler(t *testing.T) {
	t.Parallel()
	const grantURN = "urn:example:grant-type:cg-008"
	handler := &recordingCustomGrant{
		name: grantURN,
		response: op.CustomGrantResponse{ //nolint:gosec // G101 false positive: AccessToken is a fixed-string test fixture, not a credential.
			AccessToken:    "issued-cg-008",
			AccessTokenTTL: 60_000_000_000, // 60 seconds
		},
	}
	tk, rp := newCGProvider(t, handler, []string{"openid"}, nil)
	status, body := postCustomGrant(t, tk, url.Values{
		"grant_type": []string{grantURN},
	}, rp.ID, cgClientSecret)
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", status, body)
	}
	if got := body["access_token"]; got != "issued-cg-008" {
		t.Errorf("access_token=%v want issued-cg-008", got)
	}
	if got := body["token_type"]; got != "Bearer" {
		t.Errorf("token_type=%v want Bearer", got)
	}
	if got, _ := body["expires_in"].(float64); got != 60 {
		t.Errorf("expires_in=%v want 60", got)
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if handler.gotKid != rp.ID {
		t.Errorf("handler observed client.ID=%q, want %q", handler.gotKid, rp.ID)
	}
}

// TestScenario_CG_009_HandlerReceivesClientEntityOnly is OOS — the
// "ctx.oidc.entities" model the row presupposes is a vendor-specific
// shape (the upstream JS reference OP) the library does not adopt.
// CustomGrantRequest already projects only the data the handler
// needs (Client + Subject + Form + DPoP/MTLS) — no ambient entity
// graph exists to leak.
func TestScenario_CG_009_HandlerReceivesClientEntityOnly(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: CG-009 (see catalog out_of_scope_reason)")
}

// TestScenario_CG_010_HandlerRefreshTokenWiredToLineage confirms that a
// custom grant whose handler sets CustomGrantResponse.IssueRefreshToken
// causes the OP to mint and persist an OP-owned refresh token (the
// handler signals intent only). The issued token is exchangeable at the
// token endpoint, proving it was persisted through the OP's own
// refresh-token store and rides the standard rotation lineage rather
// than being echoed verbatim. Issuance is gated on the client being
// registered for the refresh_token grant.
//
// Spec: RFC 6749 §6 / RFC 9700 §2.2.2.
func TestScenario_CG_010_HandlerRefreshTokenWiredToLineage(t *testing.T) {
	t.Parallel()
	const grantURN = "urn:example:grant-type:cg-010"
	const subject = "user-cg-010"
	handler := &recordingCustomGrant{
		name: grantURN,
		response: op.CustomGrantResponse{ //nolint:gosec // G101 false positive: AccessToken is a fixed-string test fixture, not a credential.
			AccessToken:       "issued-cg-010",
			IssueRefreshToken: true,
			Subject:           op.Subject(subject),
			Scope:             []string{"openid"},
		},
	}
	hash, err := op.HashClientSecret(cgClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithCustomGrant(handler)))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "cg-rp-refresh",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{grantURN, "refresh_token"},
		Scopes:                  []string{"openid"},
	})

	status, body := postCustomGrant(t, tk, url.Values{
		"grant_type": []string{grantURN},
	}, rp.ID, cgClientSecret)
	if status != http.StatusOK {
		t.Fatalf("custom grant status=%d want 200, body=%v", status, body)
	}
	rt, _ := body["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("refresh_token missing; want an OP-minted value, body=%v", body)
	}

	// Exchanging the OP-minted refresh token proves it was persisted
	// through the refresh-token store (a verbatim echo would miss the
	// registry and fail here).
	rstatus, rbody := postCustomGrant(t, tk, url.Values{
		"grant_type":    []string{"refresh_token"},
		"refresh_token": []string{rt},
	}, rp.ID, cgClientSecret)
	if rstatus != http.StatusOK {
		t.Fatalf("refresh exchange status=%d want 200, body=%v", rstatus, rbody)
	}
	if at, _ := rbody["access_token"].(string); at == "" {
		t.Errorf("refresh exchange returned no access_token, body=%v", rbody)
	}
}

// TestCustomGrant_IDTokenSigning_FromExtraClaims confirms the OP signs
// a fresh id_token from the response Subject + AuthTime + ExtraClaims
// when the handler returns an empty IDToken and Scope contains "openid".
// The row is not in the spec catalogue: it pins the OP-side enhancement
// the dispatcher's contract documents (no embedder-side signing key
// required for the openid case).
func TestCustomGrant_IDTokenSigning_FromExtraClaims(t *testing.T) {
	t.Parallel()
	const grantURN = "urn:example:grant-type:cg-idt-extra"
	const subject = "user-cg-idt-1"
	authTime := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	handler := &recordingCustomGrant{
		name: grantURN,
		response: op.CustomGrantResponse{ //nolint:gosec // G101 false positive: AccessToken is a fixed-string test fixture, not a credential.
			AccessToken:    "issued-cg-idt-1",
			AccessTokenTTL: 60 * time.Second,
			Subject:        subject,
			AuthTime:       authTime,
			Scope:          []string{"openid"},
			ExtraClaims: map[string]any{
				"role":     "operator",
				"team_ref": "ops-42",
			},
		},
	}
	tk, rp := newCGProvider(t, handler, []string{"openid"}, nil)
	status, body := postCustomGrant(t, tk, url.Values{
		"grant_type": []string{grantURN},
	}, rp.ID, cgClientSecret)
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", status, body)
	}
	idToken, _ := body["id_token"].(string)
	if idToken == "" {
		t.Fatalf("id_token absent or empty: body=%v", body)
	}
	claims := decodeCGJWTClaims(t, idToken)
	if claims["iss"] != tk.Issuer {
		t.Errorf("iss=%v want %q", claims["iss"], tk.Issuer)
	}
	if claims["sub"] != subject {
		t.Errorf("sub=%v want %q", claims["sub"], subject)
	}
	if claims["aud"] != rp.ID {
		t.Errorf("aud=%v want %q (single-aud bare string per RFC 7519 §4.1.3)", claims["aud"], rp.ID)
	}
	if got, _ := claims["auth_time"].(float64); int64(got) != authTime.Unix() {
		t.Errorf("auth_time=%v want %d", claims["auth_time"], authTime.Unix())
	}
	if claims["role"] != "operator" {
		t.Errorf("role=%v want operator", claims["role"])
	}
	if claims["team_ref"] != "ops-42" {
		t.Errorf("team_ref=%v want ops-42", claims["team_ref"])
	}
}

// TestCustomGrant_IDTokenSigning_RejectsOpenIDWithoutSubject confirms
// the OP rejects a handler response that pairs Scope=["openid"] with an
// empty Subject — the id_token "sub" claim is REQUIRED per OIDC Core
// 1.0 §2 and silently dropping it would mint a malformed token.
func TestCustomGrant_IDTokenSigning_RejectsOpenIDWithoutSubject(t *testing.T) {
	t.Parallel()
	const grantURN = "urn:example:grant-type:cg-idt-nosub"
	handler := &recordingCustomGrant{
		name: grantURN,
		response: op.CustomGrantResponse{ //nolint:gosec // G101 false positive: AccessToken is a fixed-string test fixture, not a credential.
			AccessToken:    "issued-cg-idt-2",
			AccessTokenTTL: 60 * time.Second,
			Scope:          []string{"openid"},
		},
	}
	tk, rp := newCGProvider(t, handler, []string{"openid"}, nil)
	status, body := postCustomGrant(t, tk, url.Values{
		"grant_type": []string{grantURN},
	}, rp.ID, cgClientSecret)
	if status != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500, body=%v", status, body)
	}
	if got := body["error"]; got != "server_error" {
		t.Errorf("error=%v want server_error", got)
	}
}

// TestCustomGrant_IDTokenPassthrough confirms a non-empty handler
// IDToken flows through verbatim; the OP does not re-sign or
// re-format it.
func TestCustomGrant_IDTokenPassthrough(t *testing.T) {
	t.Parallel()
	const grantURN = "urn:example:grant-type:cg-idt-pass"
	const preset = "header.payload.signature"
	handler := &recordingCustomGrant{
		name: grantURN,
		response: op.CustomGrantResponse{ //nolint:gosec // G101 false positive: AccessToken is a fixed-string test fixture, not a credential.
			AccessToken:    "issued-cg-idt-3",
			AccessTokenTTL: 60 * time.Second,
			IDToken:        preset,
			Scope:          []string{"openid"},
		},
	}
	tk, rp := newCGProvider(t, handler, []string{"openid"}, nil)
	status, body := postCustomGrant(t, tk, url.Values{
		"grant_type": []string{grantURN},
	}, rp.ID, cgClientSecret)
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", status, body)
	}
	if got := body["id_token"]; got != preset {
		t.Errorf("id_token=%v want %q (verbatim passthrough)", got, preset)
	}
}

// decodeCGJWTClaims pulls the payload claims out of a JWS Compact
// Serialisation without verifying the signature. Verifying would
// re-test JWS framing, which the IDT-suite already covers.
func decodeCGJWTClaims(tb testing.TB, jws string) map[string]any {
	tb.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		tb.Fatalf("jwt parts=%d want 3 (value=%q)", len(parts), jws)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		tb.Fatalf("decode payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		tb.Fatalf("unmarshal claims: %v", err)
	}
	return claims
}
