package scenarios_test

// Catalog: test/scenarios/catalog/device_code.yaml (DEV-NNN)
// Spec:
//   - RFC 8628 — OAuth 2.0 Device Authorization Grant
//   - RFC 6749 §5.1 / §5.2 — Token response and error format
//   - RFC 8707 — OAuth 2.0 Resource Indicators
//   - OpenID Connect Core 1.0 §3.1.3 / §11
//   - RFC 8414 — Discovery (device_authorization_endpoint)

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/devicecode"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/devicecodekit"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// devURNDeviceCode is the wire form of the device_code grant_type. The
// constant is hard-coded here rather than imported from op/grant so a
// rename of the public symbol surfaces as a loud test failure on the
// catalog row that pins the discovery / wire shape.
const devURNDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"

// devClientSecret is the deterministic confidential-client secret the
// DEV suite reuses. Mirrors the CG / IDT suites' style: a fixed
// fixture so a failure trace can be replayed without seeding the RNG.
//
//nolint:gosec // test fixture: not a real credential.
const devClientSecret = "dev-client-secret"

// devDefaultSubject is the subject the suite stamps on Approved
// device-code records. Kept distinct from scenariokit.DefaultSubject so
// a future refactor of the code-flow helper does not silently change
// the device flow's expected sub claim.
const devDefaultSubject = "user-dev"

// devProvider bundles the testkit provider with a pre-registered
// device_code-capable confidential client. The struct exists so each
// row's setup boilerplate stays a single line.
type devProvider struct {
	tk     *testkit.Provider
	client *store.Client
}

// newDevProvider constructs a fully wired provider with the device_code
// grant enabled and a single confidential client whose registered
// grant_types include both authorization_code (testkit's default) and
// the device_code URN. scopes lets the caller widen the scope set
// per-row.
func newDevProvider(t *testing.T, scopes []string) *devProvider {
	return newDevProviderWithResources(t, scopes, nil)
}

// newDevProviderWithResources is the resource-aware variant of
// [newDevProvider]: it threads resources onto the registered client's
// Resources allowlist so /device_authorization can admit the values
// the test row sends. A nil/empty resources slice matches the
// default helper. extra testkit options (e.g. a pinned clock) are
// appended so a row can make the OP's notion of "now" deterministic.
func newDevProviderWithResources(t *testing.T, scopes, resources []string, extra ...testkit.Option) *devProvider {
	t.Helper()
	hash, err := op.HashClientSecret(devClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	opts := append([]testkit.Option{testkit.WithOptions(op.WithDeviceCodeGrant())}, extra...)
	tk := testkit.NewProvider(t, opts...)
	client := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "dev-rp",
		SecretHash:              hash,
		Scopes:                  scopes,
		Resources:               append([]string(nil), resources...),
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes: []string{
			"authorization_code",
			"refresh_token",
			devURNDeviceCode,
		},
	})
	return &devProvider{tk: tk, client: client}
}

// deviceAuthForm wraps a form-encoded POST against /device_authorization
// using the registered client's basic-auth credentials. It returns the
// status code and the decoded JSON body (or nil on a non-JSON response).
func (p *devProvider) deviceAuthForm(t *testing.T, form url.Values) (int, map[string]any, http.Header) {
	t.Helper()
	return p.deviceAuthFormWithAuth(t, form, p.client.ID, devClientSecret, "application/x-www-form-urlencoded")
}

// deviceAuthFormWithAuth lets a caller vary the basic-auth credentials
// or the Content-Type. The helper returns (status, decoded body,
// response headers); the body is nil when the response is not JSON.
func (p *devProvider) deviceAuthFormWithAuth(t *testing.T, form url.Values, user, pass, contentType string) (int, map[string]any, http.Header) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		p.tk.Server.URL+"/oidc/device_authorization", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /device_authorization: %v", err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := p.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /device_authorization: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var decoded map[string]any
	if len(body) > 0 && strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")), "application/json") {
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatalf("unmarshal /device_authorization body=%q: %v", body, err)
		}
	}
	return resp.StatusCode, decoded, resp.Header.Clone()
}

// tokenForm POSTs a form-encoded request to /token using HTTP Basic
// auth and returns (status, decoded body).
func (p *devProvider) tokenForm(t *testing.T, form url.Values) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		p.tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /token: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(p.client.ID, devClientSecret)
	resp, err := p.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var decoded map[string]any
	if len(body) > 0 {
		if err := json.Unmarshal(body, &decoded); err != nil {
			t.Fatalf("unmarshal /token body=%q: %v", body, err)
		}
	}
	return resp.StatusCode, decoded
}

// issueDeviceCode performs the full /device_authorization round-trip
// and returns the device_code value the substore later resolves. The
// helper fails the test fast on any non-200 response so callers focus
// on the post-issuance flow.
func (p *devProvider) issueDeviceCode(t *testing.T, scope string) string {
	t.Helper()
	form := url.Values{}
	if scope != "" {
		form.Set("scope", scope)
	}
	status, body, _ := p.deviceAuthForm(t, form)
	if status != http.StatusOK {
		t.Fatalf("/device_authorization status=%d body=%v", status, body)
	}
	dc, _ := body["device_code"].(string)
	if dc == "" {
		t.Fatalf("/device_authorization body missing device_code: %v", body)
	}
	return dc
}

// approveDeviceCode walks the substore directly to flip a Pending
// record to Approved. The HTML-form verification page is delegated to
// the embedder (catalog rows DEV-060..DEV-090 OOS), so tests that
// drive the polling path skip the form by writing the same status the
// embedder's interaction.Driver would write after a confirm click.
// AuthTime is stamped with the current wall clock; tests that assert
// the id_token auth_time go through approveDeviceCodeAt to control
// the stamped value directly.
func (p *devProvider) approveDeviceCode(t *testing.T, deviceCode, subject string) {
	t.Helper()
	p.approveDeviceCodeAt(t, deviceCode, subject, time.Now().UTC())
}

// approveDeviceCodeAt is the deterministic variant of
// [approveDeviceCode]: callers supply the AuthTime the substore
// stamps so id_token auth_time assertions remain stable across runs.
func (p *devProvider) approveDeviceCodeAt(t *testing.T, deviceCode, subject string, authTime time.Time) {
	t.Helper()
	if err := p.tk.Store.DeviceCodes().Approve(context.Background(), deviceCode, subject, authTime); err != nil {
		t.Fatalf("DeviceCodes.Approve: %v", err)
	}
}

// denyDeviceCode flips a Pending record to Denied with the given
// reason. Mirrors approveDeviceCode for the access_denied surface.
func (p *devProvider) denyDeviceCode(t *testing.T, deviceCode, reason string) {
	t.Helper()
	if err := p.tk.Store.DeviceCodes().Deny(context.Background(), deviceCode, reason); err != nil {
		t.Fatalf("DeviceCodes.Deny: %v", err)
	}
}

// fetchDevDiscovery returns the OP's discovery document as a decoded
// JSON map. Duplicates the discovery_test.go helper so the DEV suite
// does not depend on the discovery suite's package-private symbol.
func fetchDevDiscovery(t *testing.T, base string) map[string]any {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		base+"/.well-known/openid-configuration", nil)
	if err != nil {
		t.Fatalf("NewRequest discovery: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status=%d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read discovery body: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("unmarshal discovery: %v", err)
	}
	return doc
}

// devDecodeIDToken returns the decoded claims of a compact JWS
// id_token. Mirrors decodeScenarioJWTClaims so the DEV suite stays
// self-contained.
func devDecodeIDToken(t *testing.T, jws string) map[string]any {
	t.Helper()
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token has %d parts, want 3", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode id_token payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal id_token claims: %v (raw=%q)", err, raw)
	}
	return claims
}

// expectError asserts the body shape of an RFC 6749 §5.2 error
// envelope. The helper short-circuits the boilerplate that every
// rejection row would otherwise repeat.
func expectError(t *testing.T, body map[string]any, wantCode string) {
	t.Helper()
	got, _ := body["error"].(string)
	if got != wantCode {
		t.Errorf("error=%q want %q (body=%v)", got, wantCode, body)
	}
	if _, present := body["access_token"]; present {
		t.Errorf("rejection must not mint access_token: %v", body)
	}
}

// ---------------------------------------------------------------------
// /device_authorization endpoint behaviour
// ---------------------------------------------------------------------

// TestScenario_DEV_001_DeviceAuthRejectsNonFormBody pins the
// content-type gate on /device_authorization. The endpoint accepts only
// application/x-www-form-urlencoded per RFC 8628 §3.1; any other media
// type yields 400 invalid_request.
//
// Spec: RFC 8628 §3.1, RFC 6749 §3.2.
func TestScenario_DEV_001_DeviceAuthRejectsNonFormBody(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid"})

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		p.tk.Server.URL+"/oidc/device_authorization", strings.NewReader(`{"scope":"openid"}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(p.client.ID, devClientSecret)
	resp, err := p.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, body)
	}
	expectError(t, env, "invalid_request")
}

// TestScenario_DEV_002_DeviceAuthRequiresGrantTypeAllowance pins the
// per-client gate on /device_authorization: a client whose registered
// grant_types do not include the device_code URN MUST be rejected
// before any record is persisted. The handler returns
// 400 unauthorized_client per RFC 8628 §3.1's per-client gate.
//
// Spec: RFC 8628 §3.1, RFC 7591.
func TestScenario_DEV_002_DeviceAuthRequiresGrantTypeAllowance(t *testing.T) {
	t.Parallel()
	hash, err := op.HashClientSecret(devClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(op.WithDeviceCodeGrant()))
	client := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "dev-rp-002",
		SecretHash:              hash,
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code"}, // no device_code
	})

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/device_authorization", strings.NewReader("scope=openid"))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ID, devClientSecret)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, body)
	}
	expectError(t, env, "unauthorized_client")
}

// TestScenario_DEV_003_DeviceAuthRejectsUnknownClient pins the client
// authentication gate on /device_authorization: an unknown or wrongly-
// authenticated client receives 401 invalid_client per RFC 6749 §5.2.
//
// Spec: RFC 6749 §5.2, RFC 8628 §3.1.
func TestScenario_DEV_003_DeviceAuthRejectsUnknownClient(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid"})

	status, body, _ := p.deviceAuthFormWithAuth(t, url.Values{"scope": {"openid"}},
		"no-such-client", "no-such-secret", "application/x-www-form-urlencoded")
	if status != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401 body=%v", status, body)
	}
	expectError(t, body, "invalid_client")
}

// TestScenario_DEV_004_DeviceAuthRejectsRequestParameter is OOS — the
// request parameter (OIDC Core §6.1) is not in the RFC 8628 §3.1
// parameter set; v0.9.x ignores unknown form keys. See
// catalog out_of_scope_reason.
func TestScenario_DEV_004_DeviceAuthRejectsRequestParameter(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-004 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_005_DeviceAuthRejectsRequestURIParameter is OOS — see
// catalog out_of_scope_reason.
func TestScenario_DEV_005_DeviceAuthRejectsRequestURIParameter(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-005 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_006_DeviceAuthRejectsRegistrationParameter is OOS —
// see catalog out_of_scope_reason.
func TestScenario_DEV_006_DeviceAuthRejectsRegistrationParameter(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-006 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_007_DeviceAuthSuccessResponseShape pins the §3.2
// success envelope: device_code, user_code, verification_uri,
// verification_uri_complete, expires_in, interval. The response body
// MUST be application/json with a no-store cache directive.
//
// Spec: RFC 8628 §3.2.
func TestScenario_DEV_007_DeviceAuthSuccessResponseShape(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid", "profile"})

	status, body, headers := p.deviceAuthForm(t, url.Values{"scope": {"openid"}})
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", status, body)
	}
	if got := headers.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(got), "application/json") {
		t.Errorf("Content-Type=%q want application/json*", got)
	}
	if got := headers.Get("Cache-Control"); !strings.Contains(strings.ToLower(got), "no-store") {
		t.Errorf("Cache-Control=%q must contain no-store", got)
	}

	for _, field := range []string{"device_code", "user_code", "verification_uri", "verification_uri_complete"} {
		if got, _ := body[field].(string); got == "" {
			t.Errorf("%s missing/empty: %v", field, body)
		}
	}
	for _, field := range []string{"expires_in", "interval"} {
		got, ok := body[field].(float64)
		if !ok || got <= 0 {
			t.Errorf("%s=%v want positive number", field, body[field])
		}
	}
	uri, _ := body["verification_uri"].(string)
	complete, _ := body["verification_uri_complete"].(string)
	userCode, _ := body["user_code"].(string)
	wantComplete := uri + "?user_code=" + url.QueryEscape(userCode)
	if complete != wantComplete {
		t.Errorf("verification_uri_complete=%q want %q", complete, wantComplete)
	}
}

// TestScenario_DEV_007B_DeviceAuthRejectsDuplicateScope pins the
// RFC 6749 §3.2 single-valued parameter rule on /device_authorization:
// a repeated scope field MUST be rejected instead of silently using the
// first value and issuing a device_code for a narrower grant.
func TestScenario_DEV_007B_DeviceAuthRejectsDuplicateScope(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid", "profile"})

	status, body, _ := p.deviceAuthForm(t, url.Values{"scope": {"openid", "profile"}})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectError(t, body, "invalid_request")
}

// TestScenario_DEV_008_DeviceCodePersistedWithStrippedParams is OOS —
// the 'strip authorization-endpoint params' assertion is vendor-
// specific. See catalog out_of_scope_reason.
func TestScenario_DEV_008_DeviceCodePersistedWithStrippedParams(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-008 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_009_DeviceAuthBypassesPARRequirement is OOS — no
// per-client PAR gate on /device_authorization in v0.9.x. See catalog
// out_of_scope_reason.
func TestScenario_DEV_009_DeviceAuthBypassesPARRequirement(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-009 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_010_DeviceAuthAcceptsHTTPBasicClientAuth pins the
// client_secret_basic authentication path on /device_authorization.
// The endpoint shares the client-authentication contract with /token
// and /par, so credentials in the Authorization: Basic header
// authenticate the client without a redundant client_id form
// parameter.
//
// Spec: RFC 6749 §2.3.1, RFC 8628 §3.1.
func TestScenario_DEV_010_DeviceAuthAcceptsHTTPBasicClientAuth(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid"})

	// Basic auth is the only credential channel; no client_id form key.
	status, body, _ := p.deviceAuthForm(t, url.Values{"scope": {"openid"}})
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", status, body)
	}
	if dc, _ := body["device_code"].(string); dc == "" {
		t.Errorf("device_code missing: %v", body)
	}
}

// TestScenario_DEV_011_DeviceAuthSuccessResolvesEntities is OOS —
// vendor framework idiom, no analog in v0.9.x. See catalog
// out_of_scope_reason.
func TestScenario_DEV_011_DeviceAuthSuccessResolvesEntities(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-011 (see catalog out_of_scope_reason)")
}

// ---------------------------------------------------------------------
// device_code grant at /token
// ---------------------------------------------------------------------

// TestScenario_DEV_020_DeviceCodeGrantNonConformIDTokenClaims is OOS —
// no conformIdTokenClaims knob in v0.9.x. See catalog out_of_scope_reason.
func TestScenario_DEV_020_DeviceCodeGrantNonConformIDTokenClaims(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-020 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_021_DeviceCodeGrantConformIDTokenClaims is OOS — see
// catalog out_of_scope_reason.
func TestScenario_DEV_021_DeviceCodeGrantConformIDTokenClaims(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-021 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_022_DeviceCodeGrantWithoutOfflineAccess is OOS — no
// gty stamp in v0.9.x. See catalog out_of_scope_reason.
func TestScenario_DEV_022_DeviceCodeGrantWithoutOfflineAccess(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-022 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_023_DeviceCodeGrantWithOfflineAccess is OOS — same
// as DEV-022. See catalog out_of_scope_reason.
func TestScenario_DEV_023_DeviceCodeGrantWithOfflineAccess(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-023 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_024_TokenRequestMissingDeviceCode pins the
// required-parameter gate on the /token device_code grant: a request
// missing the device_code form parameter is rejected with 400
// invalid_request.
//
// Spec: RFC 8628 §3.4.
func TestScenario_DEV_024_TokenRequestMissingDeviceCode(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid"})

	status, body := p.tokenForm(t, url.Values{
		"grant_type": {devURNDeviceCode},
		// no device_code
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectError(t, body, "invalid_request")
}

// TestScenario_DEV_025_TokenRequestUnknownDeviceCode is OOS — v0.9.x
// maps not-found to expired_token, not invalid_grant. See catalog
// out_of_scope_reason; the not-found→expired_token path is exercised
// via DEV-028 (expired record) which surfaces the same wire code.
func TestScenario_DEV_025_TokenRequestUnknownDeviceCode(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-025 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_026_TokenRequestAccountNotFound is OOS — no
// findAccount hook on the device-code redemption path. See catalog
// out_of_scope_reason.
func TestScenario_DEV_026_TokenRequestAccountNotFound(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-026 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_027_TokenRequestClientMismatch pins the cross-
// client gate: a device_code issued for client A but presented by
// client B is rejected with 400 invalid_grant. The OP refuses to leak
// presence ("device_code exists for a different client") via a
// distinct wire code.
//
// Spec: RFC 8628 §3.4.
func TestScenario_DEV_027_TokenRequestClientMismatch(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid"})

	// Issue a device_code for the registered client.
	deviceCode := p.issueDeviceCode(t, "openid")

	// Register a second confidential client with the device_code grant.
	hash, err := op.HashClientSecret(devClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	other := p.tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "dev-rp-other",
		SecretHash:              hash,
		Scopes:                  []string{"openid"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{devURNDeviceCode},
	})

	form := url.Values{
		"grant_type":  {devURNDeviceCode},
		"device_code": {deviceCode},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		p.tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(other.ID, devClientSecret)
	resp, err := p.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var env map[string]any
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("body is not JSON: %v (raw=%q)", err, body)
	}
	expectError(t, env, "invalid_grant")
}

// TestScenario_DEV_028_TokenRequestExpiredDeviceCode pins the
// expired_token wire code: a device_code whose ExpiresAt has elapsed
// (modelled here by writing a record with ExpiresAt in the past
// directly through the substore) returns 400 expired_token. The
// substore reports expired records as not-found, and the token
// endpoint maps that to expired_token so an attacker cannot
// distinguish "expired" from "never existed".
//
// Spec: RFC 8628 §3.5.
func TestScenario_DEV_028_TokenRequestExpiredDeviceCode(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid"})

	// Seed an expired record directly. The wire device_code is
	// hashed-on-store, so the ID we present here is the value we'll
	// read back from FindByDeviceCode (the substore stores the digest
	// internally and accepts the raw value at the lookup site).
	const wireCode = "expired-device-code-fixture-DEV-028"
	now := time.Now()
	rec := &store.DeviceCode{
		ID:        wireCode,
		UserCode:  "EXPIRED1",
		ClientID:  p.client.ID,
		Scope:     []string{"openid"},
		Interval:  5 * time.Second,
		IssuedAt:  now.Add(-30 * time.Minute),
		ExpiresAt: now.Add(-time.Minute),
		Status:    store.DeviceCodeStatusPending,
	}
	if err := p.tk.Store.DeviceCodes().Save(context.Background(), rec); err != nil {
		t.Fatalf("DeviceCodes.Save: %v", err)
	}

	status, body := p.tokenForm(t, url.Values{
		"grant_type":  {devURNDeviceCode},
		"device_code": {wireCode},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectError(t, body, "expired_token")
}

// TestScenario_DEV_029_FirstRedemptionMarksDeviceCodeConsumed is OOS —
// internal storage shape, not wire-observable. See catalog
// out_of_scope_reason; the observable consequence (replay rejected) is
// pinned by DEV-096.
func TestScenario_DEV_029_FirstRedemptionMarksDeviceCodeConsumed(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-029 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_030_TokenRequestReplayConsumedDeviceCode is OOS —
// v0.9.x maps replay to expired_token, not invalid_grant. See catalog
// out_of_scope_reason; DEV-096 pins the actual wire code.
func TestScenario_DEV_030_TokenRequestReplayConsumedDeviceCode(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-030 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_031_TokenRequestAuthorizationPending pins the
// pre-approval poll gate: a /token poll for a device_code whose
// substore record is in the Pending state returns 400
// authorization_pending per RFC 8628 §3.5.
//
// Spec: RFC 8628 §3.5.
func TestScenario_DEV_031_TokenRequestAuthorizationPending(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid"})

	deviceCode := p.issueDeviceCode(t, "openid")

	status, body := p.tokenForm(t, url.Values{
		"grant_type":  {devURNDeviceCode},
		"device_code": {deviceCode},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectError(t, body, "authorization_pending")
}

// TestScenario_DEV_032_TokenRequestCustomResolvedError is OOS — no
// custom error pass-through in v0.9.x. See catalog out_of_scope_reason.
func TestScenario_DEV_032_TokenRequestCustomResolvedError(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-032 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_033_TokenRequestStandardResolvedError pins the
// access_denied wire code: a device_code whose substore record was
// transitioned to Denied (via DeviceCodeStore.Deny) returns 400
// access_denied at the next /token poll.
//
// Spec: RFC 8628 §3.5.
func TestScenario_DEV_033_TokenRequestStandardResolvedError(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid"})

	deviceCode := p.issueDeviceCode(t, "openid")
	p.denyDeviceCode(t, deviceCode, "user_denied")

	status, body := p.tokenForm(t, url.Values{
		"grant_type":  {devURNDeviceCode},
		"device_code": {deviceCode},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectError(t, body, "access_denied")
}

// ---------------------------------------------------------------------
// Charset / mask configuration — all OOS (v0.9.x fixes Crockford Base32)
// ---------------------------------------------------------------------

// TestScenario_DEV_040_CharsetDigitsAccepted is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_040_CharsetDigitsAccepted(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-040 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_041_CharsetBase20Accepted is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_041_CharsetBase20Accepted(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-041 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_042_UnknownCharsetRejectedAtConstruction is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_042_UnknownCharsetRejectedAtConstruction(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-042 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_043_MaskWithSpacesAccepted is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_043_MaskWithSpacesAccepted(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-043 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_044_MaskWithHyphensAccepted is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_044_MaskWithHyphensAccepted(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-044 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_045_MaskWithDisallowedCharRejected is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_045_MaskWithDisallowedCharRejected(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-045 (see catalog out_of_scope_reason)")
}

// ---------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------

// TestScenario_DEV_046_DeviceEndpointAdvertisedInDiscovery pins the
// discovery surface: with the device_code grant configured, the OP's
// /.well-known/openid-configuration MUST include
// device_authorization_endpoint pointing under the OP's mount prefix.
//
// Spec: RFC 8414 §2, RFC 8628 §4.
func TestScenario_DEV_046_DeviceEndpointAdvertisedInDiscovery(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid"})
	doc := fetchDevDiscovery(t, p.tk.Server.URL)

	endpoint, _ := doc["device_authorization_endpoint"].(string)
	if endpoint == "" {
		t.Fatalf("device_authorization_endpoint missing from discovery: %v", doc)
	}
	if !strings.HasPrefix(endpoint, p.tk.Issuer) {
		t.Errorf("device_authorization_endpoint=%q must be under issuer %q", endpoint, p.tk.Issuer)
	}
	if !strings.HasSuffix(endpoint, "/device_authorization") {
		t.Errorf("device_authorization_endpoint=%q must end with /device_authorization", endpoint)
	}
}

// ---------------------------------------------------------------------
// User-facing /device verification UI — all OOS
// ---------------------------------------------------------------------

// TestScenario_DEV_060_VerificationFormRendersWithCSRFSecret is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_060_VerificationFormRendersWithCSRFSecret(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-060 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_061_PrefilledFormAutoSubmits is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_061_PrefilledFormAutoSubmits(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-061 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_062_UserCodeInputHTMLEscaped is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_062_UserCodeInputHTMLEscaped(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-062 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_063_PostDeviceConfirmRendersConfirmForm is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_063_PostDeviceConfirmRendersConfirmForm(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-063 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_064_PostDeviceMissingUserCodeReRenders is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_064_PostDeviceMissingUserCodeReRenders(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-064 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_065_PostDeviceUnknownCodeReRenders is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_065_PostDeviceUnknownCodeReRenders(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-065 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_066_PostDeviceExpiredCodeReRenders is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_066_PostDeviceExpiredCodeReRenders(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-066 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_067_PostDeviceAlreadyUsedCodeReRenders is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_067_PostDeviceAlreadyUsedCodeReRenders(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-067 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_068_PostDeviceInvalidClientEmitsAudit is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_068_PostDeviceInvalidClientEmitsAudit(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-068 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_069_PostDeviceMissingCSRFStateEmitsAudit is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_069_PostDeviceMissingCSRFStateEmitsAudit(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-069 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_070_PostDeviceCSRFTokenMismatchEmitsAudit is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_070_PostDeviceCSRFTokenMismatchEmitsAudit(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-070 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_071_PostDeviceAbortPersistsAccessDenied is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_071_PostDeviceAbortPersistsAccessDenied(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-071 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_072_PostDeviceConfirmAssignsAccountAndAuthTime is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_072_PostDeviceConfirmAssignsAccountAndAuthTime(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-072 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_073_PostDeviceConfirmPersistsSidViaClient is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_073_PostDeviceConfirmPersistsSidViaClient(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-073 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_074_PostDeviceConfirmPersistsSidViaClaims is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_074_PostDeviceConfirmPersistsSidViaClaims(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-074 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_075_UserCodeNormalizesWhitespaceAndCase is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_075_UserCodeNormalizesWhitespaceAndCase(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-075 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_080_ResumeWithoutCookieReportsSessionNotFound is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_080_ResumeWithoutCookieReportsSessionNotFound(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-080 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_081_ResumeWithMissingInteractionReportsSessionNotFound is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_081_ResumeWithMissingInteractionReportsSessionNotFound(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-081 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_082_ResumeWithMissingDeviceCodeReportsNotFound is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_082_ResumeWithMissingDeviceCodeReportsNotFound(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-082 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_083_ResumeWithExpiredDeviceCodeReportsExpired is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_083_ResumeWithExpiredDeviceCodeReportsExpired(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-083 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_084_ResumeWithAccountAssignedReportsAlreadyUsed is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_084_ResumeWithAccountAssignedReportsAlreadyUsed(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-084 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_085_ResumeWithAccessDeniedReportsAlreadyUsed is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_085_ResumeWithAccessDeniedReportsAlreadyUsed(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-085 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_086_ResumeAfterLoginDefaultsToPermanentSession is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_086_ResumeAfterLoginDefaultsToPermanentSession(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-086 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_087_ResumeAfterLoginRememberTrue is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_087_ResumeAfterLoginRememberTrue(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-087 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_088_ResumeAfterLoginRememberFalseTransient is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_088_ResumeAfterLoginRememberFalseTransient(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-088 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_089_ResumeWithSubjectChangeRendersLogoutForm is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_089_ResumeWithSubjectChangeRendersLogoutForm(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-089 (see catalog out_of_scope_reason)")
}

// TestScenario_DEV_090_ResumeAfterInteractionAbortError is OOS — see catalog out_of_scope_reason.
func TestScenario_DEV_090_ResumeAfterInteractionAbortError(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DEV-090 (see catalog out_of_scope_reason)")
}

// ---------------------------------------------------------------------
// New v0.9.x behaviour rows
// ---------------------------------------------------------------------

// TestScenario_DEV_091_DeviceCodeApprovedRedeemsTokens pins the happy
// path: /device_authorization issues a (device_code, user_code) pair;
// the embedder calls DeviceCodeStore.Approve(device_code, subject);
// the next /token poll returns 200 with access_token (Bearer),
// expires_in, scope, and (because openid is in the granted scope) an
// id_token whose iss / aud / sub match the OP / client / approved
// subject.
//
// Spec: RFC 8628 §3.5, OIDC Core §3.1.3.
func TestScenario_DEV_091_DeviceCodeApprovedRedeemsTokens(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid", "profile"})

	deviceCode := p.issueDeviceCode(t, "openid")
	p.approveDeviceCode(t, deviceCode, devDefaultSubject)

	status, body := p.tokenForm(t, url.Values{
		"grant_type":  {devURNDeviceCode},
		"device_code": {deviceCode},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", status, body)
	}
	if at, _ := body["access_token"].(string); at == "" {
		t.Errorf("access_token missing/empty: %v", body)
	}
	if got, _ := body["token_type"].(string); got != "Bearer" {
		t.Errorf("token_type=%v want Bearer", body["token_type"])
	}
	if got, ok := body["expires_in"].(float64); !ok || got <= 0 {
		t.Errorf("expires_in=%v want positive number", body["expires_in"])
	}
	if got, _ := body["scope"].(string); got != "openid" {
		t.Errorf("scope=%q want openid", got)
	}

	idToken, _ := body["id_token"].(string)
	if idToken == "" {
		t.Fatalf("id_token missing on openid grant: %v", body)
	}
	claims := devDecodeIDToken(t, idToken)
	if got, _ := claims["iss"].(string); got != p.tk.Issuer {
		t.Errorf("iss=%q want %q", got, p.tk.Issuer)
	}
	if got, _ := claims["sub"].(string); got != devDefaultSubject {
		t.Errorf("sub=%q want %q", got, devDefaultSubject)
	}
	switch aud := claims["aud"].(type) {
	case string:
		if aud != p.client.ID {
			t.Errorf("aud=%q want %q", aud, p.client.ID)
		}
	case []any:
		if len(aud) != 1 {
			t.Errorf("aud=%v want single-entry [%q]", aud, p.client.ID)
		} else if got, _ := aud[0].(string); got != p.client.ID {
			t.Errorf("aud[0]=%q want %q", got, p.client.ID)
		}
	default:
		t.Errorf("aud has unexpected type %T (value=%v)", aud, aud)
	}
}

// TestScenario_DEV_092_DeviceAuthRejectsOutOfSetScope pins the scope
// gate at /device_authorization: a request whose scope contains a
// value outside the client's registered Scopes is rejected with 400
// invalid_scope. The handler does NOT silently narrow.
//
// Spec: RFC 8628 §3.1, RFC 6749 §3.3.
func TestScenario_DEV_092_DeviceAuthRejectsOutOfSetScope(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid"})

	status, body, _ := p.deviceAuthForm(t, url.Values{"scope": {"openid forbidden"}})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectError(t, body, "invalid_scope")
}

// TestScenario_DEV_092B_DeviceAuthRejectsAllowedClientsScope pins the
// global scope-registry gate at /device_authorization. The requested
// scope is present in the client's registered Scopes set, but
// op.Scope.AllowedClients reserves it for a different client_id.
func TestScenario_DEV_092B_DeviceAuthRejectsAllowedClientsScope(t *testing.T) {
	t.Parallel()
	hash, err := op.HashClientSecret(devClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithDeviceCodeGrant(),
		op.WithScope(op.Scope{
			Name:           "billing:write",
			Public:         true,
			AllowedClients: []string{"svc-billing"},
		}),
	))
	client := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "dev-rp",
		SecretHash:              hash,
		Scopes:                  []string{"openid", "billing:write"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes: []string{
			"authorization_code",
			"refresh_token",
			devURNDeviceCode,
		},
	})
	p := &devProvider{tk: tk, client: client}

	status, body, _ := p.deviceAuthForm(t, url.Values{"scope": {"openid billing:write"}})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectError(t, body, "invalid_scope")
}

// TestScenario_DEV_093_DeviceAuthRejectsRelativeResource pins the
// resource-indicator gate at /device_authorization: a relative resource
// URI (no scheme, no host) is rejected with 400 invalid_target per
// RFC 8707 §2's absolute-URI requirement.
//
// Spec: RFC 8707 §2, RFC 8628 §3.1.
func TestScenario_DEV_093_DeviceAuthRejectsRelativeResource(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid"})

	status, body, _ := p.deviceAuthForm(t, url.Values{
		"scope":    {"openid"},
		"resource": {"/relative/path"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectError(t, body, "invalid_target")
}

// TestScenario_DEV_102_DeviceAuthRejectsUnregisteredResource pins
// the audience-escalation gate at /device_authorization: a request
// whose resource is a syntactically valid absolute URI but does not
// appear in the client's Resources allowlist MUST be rejected with
// 400 invalid_target.
//
// Spec: RFC 8707 §2, RFC 8628 §3.1.
func TestScenario_DEV_102_DeviceAuthRejectsUnregisteredResource(t *testing.T) {
	t.Parallel()
	p := newDevProviderWithResources(t,
		[]string{"openid"}, []string{"https://api-allowed.example"})

	status, body, _ := p.deviceAuthForm(t, url.Values{
		"scope":    {"openid"},
		"resource": {"https://api-other.example/"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectError(t, body, "invalid_target")
}

// TestScenario_DEV_103_DeviceAuthRejectsMultiResource pins the
// single-audience invariant: even when both values are individually
// in the client's allowlist, a request carrying more than one
// resource= entry MUST be rejected with 400 invalid_target rather
// than silently truncated to the first value at issuance.
//
// Spec: RFC 8707 §2, RFC 8628 §3.1.
func TestScenario_DEV_103_DeviceAuthRejectsMultiResource(t *testing.T) {
	t.Parallel()
	p := newDevProviderWithResources(t,
		[]string{"openid"},
		[]string{"https://api-a.example", "https://api-b.example"})

	form := url.Values{}
	form.Set("scope", "openid")
	form.Add("resource", "https://api-a.example/")
	form.Add("resource", "https://api-b.example/")
	status, body, _ := p.deviceAuthForm(t, form)
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400 body=%v", status, body)
	}
	expectError(t, body, "invalid_target")
}

// TestScenario_DEV_094_DeviceCodeIDTokenCarriesAtHash pins OIDC Core
// §3.1.3.6's at_hash invariant on the device_code path: the id_token
// issued alongside an access token on /token redemption MUST carry an
// at_hash claim derived from the access token; the device flow has no
// authorization code so c_hash MUST be absent and no nonce binding is
// retained across the verification ceremony so nonce MUST be absent.
//
// Spec: OIDC Core §3.1.3.6.
func TestScenario_DEV_094_DeviceCodeIDTokenCarriesAtHash(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid"})

	deviceCode := p.issueDeviceCode(t, "openid")
	p.approveDeviceCode(t, deviceCode, devDefaultSubject)

	_, body := p.tokenForm(t, url.Values{
		"grant_type":  {devURNDeviceCode},
		"device_code": {deviceCode},
	})
	idToken, _ := body["id_token"].(string)
	if idToken == "" {
		t.Fatalf("id_token missing: %v", body)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatalf("access_token missing: %v", body)
	}
	claims := devDecodeIDToken(t, idToken)
	gotHash, _ := claims["at_hash"].(string)
	if gotHash == "" {
		t.Errorf("id_token at_hash missing: %v", claims)
	}
	// at_hash = base64url(left-half(SHA-256(access_token))).
	digest := sha256.Sum256([]byte(at))
	wantHash := base64.RawURLEncoding.EncodeToString(digest[:len(digest)/2])
	if gotHash != wantHash {
		t.Errorf("at_hash=%q want %q", gotHash, wantHash)
	}
	if _, present := claims["c_hash"]; present {
		t.Errorf("c_hash MUST NOT appear on the device_code id_token: %v", claims)
	}
	if _, present := claims["nonce"]; present {
		t.Errorf("nonce MUST NOT appear on the device_code id_token: %v", claims)
	}
}

// TestScenario_DEV_095_RefreshTokenDefaultCompatibility pins the historical
// default: a refresh-capable OIDC client receives a refresh token without
// offline_access, while a client that has not registered refresh_token does
// not. The strict-policy variant belongs to DEV-STRICT-095 below.
func TestScenario_DEV_095_RefreshTokenDefaultCompatibility(t *testing.T) {
	t.Parallel()

	t.Run("open id and registered refresh grant issues token without offline access", func(t *testing.T) {
		t.Parallel()

		p := newDevProvider(t, []string{"openid"})
		deviceCode := p.issueDeviceCode(t, "openid")
		p.approveDeviceCode(t, deviceCode, devDefaultSubject)

		status, body := p.tokenForm(t, url.Values{
			"grant_type":  {devURNDeviceCode},
			"device_code": {deviceCode},
		})
		if status != http.StatusOK {
			t.Fatalf("status=%d want 200 body=%v", status, body)
		}
		if refresh, _ := body["refresh_token"].(string); refresh == "" {
			t.Fatalf("refresh_token missing under default policy: %v", body)
		}
	})

	t.Run("missing registered refresh grant suppresses token", func(t *testing.T) {
		t.Parallel()

		p := newDevProvider(t, []string{"openid", "offline_access"})
		p.client.GrantTypes = []string{"authorization_code", devURNDeviceCode}
		if err := p.tk.Store.UpdateClient(context.Background(), p.client); err != nil {
			t.Fatalf("UpdateClient: %v", err)
		}
		deviceCode := p.issueDeviceCode(t, "openid offline_access")
		p.approveDeviceCode(t, deviceCode, devDefaultSubject)

		status, body := p.tokenForm(t, url.Values{
			"grant_type":  {devURNDeviceCode},
			"device_code": {deviceCode},
		})
		if status != http.StatusOK {
			t.Fatalf("status=%d want 200 body=%v", status, body)
		}
		if _, present := body["refresh_token"]; present {
			t.Fatalf("refresh_token present without registered grant: %v", body)
		}
	})
}

// TestScenario_DEV_STRICT_095_RefreshTokenRequiresOfflineAccess pins the
// opt-in OIDC Core §11 reading. It uses the same device-code transport as
// DEV-095, so this matrix prevents the two policies from drifting apart.
func TestScenario_DEV_STRICT_095_RefreshTokenRequiresOfflineAccess(t *testing.T) {
	t.Parallel()

	newStrictProvider := func(t *testing.T) *devProvider {
		t.Helper()
		return newDevProviderWithResources(
			t,
			[]string{"openid", "offline_access"},
			nil,
			testkit.WithOptions(op.WithStrictOfflineAccess()),
		)
	}

	t.Run("no offline access suppresses token", func(t *testing.T) {
		t.Parallel()

		p := newStrictProvider(t)
		deviceCode := p.issueDeviceCode(t, "openid")
		p.approveDeviceCode(t, deviceCode, devDefaultSubject)
		status, body := p.tokenForm(t, url.Values{
			"grant_type":  {devURNDeviceCode},
			"device_code": {deviceCode},
		})
		if status != http.StatusOK {
			t.Fatalf("status=%d want 200 body=%v", status, body)
		}
		if _, present := body["refresh_token"]; present {
			t.Fatalf("refresh_token present without offline_access in strict mode: %v", body)
		}
	})

	t.Run("offline access and registered grant issue token", func(t *testing.T) {
		t.Parallel()

		p := newStrictProvider(t)
		deviceCode := p.issueDeviceCode(t, "openid offline_access")
		p.approveDeviceCode(t, deviceCode, devDefaultSubject)
		status, body := p.tokenForm(t, url.Values{
			"grant_type":  {devURNDeviceCode},
			"device_code": {deviceCode},
		})
		if status != http.StatusOK {
			t.Fatalf("status=%d want 200 body=%v", status, body)
		}
		if refresh, _ := body["refresh_token"].(string); refresh == "" {
			t.Fatalf("refresh_token missing with offline_access in strict mode: %v", body)
		}
	})
}

// TestScenario_DEV_096_TokenReplayConsumedReturnsExpired pins the
// replay path: a /token poll for an already-Consumed device_code MUST
// return 400 expired_token. The substore's atomic Consume CAS is the
// single-use guarantee; replays surface as expired_token (RFC 8628
// §3.5 reserves the code for both 'expired' and 'already consumed').
//
// Spec: RFC 8628 §3.5, RFC 6749 §10.5.
func TestScenario_DEV_096_TokenReplayConsumedReturnsExpired(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid"})

	deviceCode := p.issueDeviceCode(t, "openid")
	p.approveDeviceCode(t, deviceCode, devDefaultSubject)

	// First poll: succeeds.
	status, body := p.tokenForm(t, url.Values{
		"grant_type":  {devURNDeviceCode},
		"device_code": {deviceCode},
	})
	if status != http.StatusOK {
		t.Fatalf("first poll status=%d want 200 body=%v", status, body)
	}

	// Replay: the substore reports ErrAlreadyConsumed; the token
	// endpoint maps that to expired_token.
	status, body = p.tokenForm(t, url.Values{
		"grant_type":  {devURNDeviceCode},
		"device_code": {deviceCode},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("replay status=%d want 400 body=%v", status, body)
	}
	expectError(t, body, "expired_token")
}

// TestScenario_DEV_097_DeviceAuthGetReturnsMethodNotAllowed pins the
// HTTP-method gate on /device_authorization. The endpoint is
// exclusively form-encoded POST per RFC 8628 §3.1; a GET (or any other
// method) returns 405 with an Allow: POST response header.
//
// Spec: RFC 8628 §3.1, RFC 7231 §6.5.5.
func TestScenario_DEV_097_DeviceAuthGetReturnsMethodNotAllowed(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid"})

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		p.tk.Server.URL+"/oidc/device_authorization", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := p.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET /device_authorization: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", resp.StatusCode)
	}
	allowed := resp.Header.Values("Allow")
	if !slices.Contains(allowed, http.MethodPost) {
		t.Errorf("Allow header=%v must contain POST", allowed)
	}
}

// TestScenario_DEV_098_TokenSlowDownOnPollTooSoon pins the
// RFC 8628 §3.5 slow_down ladder. The test drives three consecutive
// /token polls against a Pending device_code: the first establishes
// the LastPolledAt baseline, the second polls below the advertised
// interval and triggers slow_down (the persisted Interval doubles),
// and the third polls below the now-doubled interval and triggers
// slow_down again (the persisted Interval doubles again). The test
// reads the Interval back through the substore between polls so the
// persistence half of the ladder is observed: a regression where
// the OP returned slow_down on the wire but failed to persist the
// doubled bar would let a malicious device keep hammering at the
// original cadence indefinitely.
//
// Spec: RFC 8628 §3.5 (slow_down).
func TestScenario_DEV_098_TokenSlowDownOnPollTooSoon(t *testing.T) {
	t.Parallel()
	// Pin the OP clock so both rapid polls observe the same instant: the
	// gap between them is deterministically zero (< FastPollFloor), so the
	// slow_down ladder is exercised without depending on wall-clock
	// scheduling. Under a loaded -race run the previous real-clock form
	// could see a >interval gap and flip to authorization_pending.
	clock := newAdvanceableClock(time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC))
	p := newDevProviderWithResources(t, []string{"openid"}, nil, testkit.WithClock(clock))

	deviceCode := p.issueDeviceCode(t, "openid")
	rec, err := p.tk.Store.DeviceCodes().FindByDeviceCode(context.Background(), deviceCode)
	if err != nil {
		t.Fatalf("FindByDeviceCode (seed): %v", err)
	}
	seedInterval := rec.Interval
	if seedInterval <= 0 {
		t.Fatalf("seed Interval = %v, want positive", seedInterval)
	}

	// Poll #1: Pending record, no prior LastPolledAt. The polling
	// discipline only escalates on a repeated poll, so the wire
	// response is authorization_pending and the persisted Interval
	// stays at the seed. The persisted LastPolledAt becomes the
	// anchor the next poll's slow_down gate compares against.
	status, body := p.tokenForm(t, url.Values{
		"grant_type":  {devURNDeviceCode},
		"device_code": {deviceCode},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("poll #1 status=%d want 400 body=%v", status, body)
	}
	expectError(t, body, "authorization_pending")
	rec, err = p.tk.Store.DeviceCodes().FindByDeviceCode(context.Background(), deviceCode)
	if err != nil {
		t.Fatalf("FindByDeviceCode after poll #1: %v", err)
	}
	if rec.Interval != seedInterval {
		t.Errorf("after poll #1 (no slow_down): Interval = %v, want %v", rec.Interval, seedInterval)
	}
	if rec.LastPolledAt == nil {
		t.Fatal("after poll #1: LastPolledAt is nil; RecordPoll did not persist the timestamp")
	}

	// Poll #2: arrives well within the advertised interval (we just
	// polled). Decision is slow_down → persisted Interval doubles.
	status, body = p.tokenForm(t, url.Values{
		"grant_type":  {devURNDeviceCode},
		"device_code": {deviceCode},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("poll #2 status=%d want 400 body=%v", status, body)
	}
	expectError(t, body, "slow_down")
	rec, err = p.tk.Store.DeviceCodes().FindByDeviceCode(context.Background(), deviceCode)
	if err != nil {
		t.Fatalf("FindByDeviceCode after poll #2: %v", err)
	}
	wantAfter2 := seedInterval * 2
	if rec.Interval != wantAfter2 {
		t.Errorf("after poll #2 (slow_down #1): Interval = %v, want %v (double of seed %v)",
			rec.Interval, wantAfter2, seedInterval)
	}

	// Poll #3: arrives still within the now-doubled interval. Decision
	// is slow_down again → persisted Interval doubles again. This is
	// the assertion that pins the regression: prior to the fix, the
	// OP returned slow_down on the wire but the persisted Interval
	// never moved off the seed value, letting the device keep hitting
	// the same bar indefinitely.
	status, body = p.tokenForm(t, url.Values{
		"grant_type":  {devURNDeviceCode},
		"device_code": {deviceCode},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("poll #3 status=%d want 400 body=%v", status, body)
	}
	expectError(t, body, "slow_down")
	rec, err = p.tk.Store.DeviceCodes().FindByDeviceCode(context.Background(), deviceCode)
	if err != nil {
		t.Fatalf("FindByDeviceCode after poll #3: %v", err)
	}
	wantAfter3 := wantAfter2 * 2
	if rec.Interval != wantAfter3 {
		t.Errorf("after poll #3 (slow_down #2): Interval = %v, want %v (double of %v)",
			rec.Interval, wantAfter3, wantAfter2)
	}
}

// TestScenario_DEV_098B_TokenPollAbuseLockout pins the polling-channel
// brute-force gate. A client that keeps polling inside the effective
// interval receives slow_down while the OP accumulates strikes; at the
// package cap the record is denied with reason "poll_abuse", and the
// next poll surfaces access_denied.
//
// Spec: RFC 8628 §3.5, RFC 8628 §5.2.
func TestScenario_DEV_098B_TokenPollAbuseLockout(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid"})

	deviceCode := p.issueDeviceCode(t, "openid")
	status, body := p.tokenForm(t, url.Values{
		"grant_type":  {devURNDeviceCode},
		"device_code": {deviceCode},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("baseline poll status=%d want 400 body=%v", status, body)
	}
	expectError(t, body, "authorization_pending")

	for i := 1; i <= int(devicecode.MaxPollViolations); i++ {
		status, body = p.tokenForm(t, url.Values{
			"grant_type":  {devURNDeviceCode},
			"device_code": {deviceCode},
		})
		if status != http.StatusBadRequest {
			t.Fatalf("slow_down poll #%d status=%d want 400 body=%v", i, status, body)
		}
		expectError(t, body, "slow_down")
	}
	rec, err := p.tk.Store.DeviceCodes().FindByDeviceCode(context.Background(), deviceCode)
	if err != nil {
		t.Fatalf("FindByDeviceCode after poll-abuse cap: %v", err)
	}
	if rec.PollViolations != devicecode.MaxPollViolations {
		t.Errorf("PollViolations = %d, want %d", rec.PollViolations, devicecode.MaxPollViolations)
	}
	if rec.Status != store.DeviceCodeStatusDenied {
		t.Errorf("Status = %v, want Denied", rec.Status)
	}
	if rec.DenyReason != "poll_abuse" {
		t.Errorf("DenyReason = %q, want poll_abuse", rec.DenyReason)
	}

	status, body = p.tokenForm(t, url.Values{
		"grant_type":  {devURNDeviceCode},
		"device_code": {deviceCode},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("post-lockout poll status=%d want 400 body=%v", status, body)
	}
	expectError(t, body, "access_denied")
}

// TestScenario_DEV_099_DiscoveryGrantTypesIncludesDeviceCode pins the
// discovery surface: with the device_code grant configured, the OP's
// grant_types_supported list MUST include the device_code URN per
// RFC 8628 §4.
//
// Spec: RFC 8414, RFC 8628 §4.
func TestScenario_DEV_099_DiscoveryGrantTypesIncludesDeviceCode(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid"})
	doc := fetchDevDiscovery(t, p.tk.Server.URL)

	raw, ok := doc["grant_types_supported"].([]any)
	if !ok {
		t.Fatalf("grant_types_supported missing or not a list: %v", doc["grant_types_supported"])
	}
	found := false
	for _, v := range raw {
		if s, _ := v.(string); s == devURNDeviceCode {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("grant_types_supported=%v must include %q", raw, devURNDeviceCode)
	}
}

// TestScenario_DEV_100_UserCodeBruteForceLockout pins the public
// brute-force gate (op/devicecodekit.VerifyUserCode). Four wrong
// submissions stay Pending; the fifth transitions the record to
// Denied with reason "user_code_lockout"; a sixth submission to the
// Denied record returns ErrAlreadyDecided without further strikes;
// the wire posture on the polling channel is access_denied (covered
// by the substore's Denied → access_denied mapping at /token).
//
// Spec: RFC 8628 §5.2, ADR 0031 §S.1.
func TestScenario_DEV_100_UserCodeBruteForceLockout(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid"})

	deviceCode := p.issueDeviceCode(t, "openid")
	rec, err := p.tk.Store.DeviceCodes().FindByDeviceCode(context.Background(), deviceCode)
	if err != nil {
		t.Fatalf("FindByDeviceCode (seed): %v", err)
	}
	correct := rec.UserCode

	deps := &devicecodekit.Deps{DeviceCodes: p.tk.Store.DeviceCodes()}

	// Strikes 1–4: mismatched submission, record stays Pending.
	for i := 1; i <= 4; i++ {
		matched, err := devicecodekit.VerifyUserCode(context.Background(), deps, deviceCode, "WRONG"+strconv.Itoa(i))
		if err != nil {
			t.Fatalf("strike #%d: VerifyUserCode err = %v", i, err)
		}
		if matched {
			t.Errorf("strike #%d: matched = true on mismatched submission", i)
		}
		got, err := p.tk.Store.DeviceCodes().FindByDeviceCode(context.Background(), deviceCode)
		if err != nil {
			t.Fatalf("strike #%d: FindByDeviceCode: %v", i, err)
		}
		if int(got.UserCodeStrikes) != i {
			t.Errorf("strike #%d: Strikes = %d, want %d", i, got.UserCodeStrikes, i)
		}
		if got.Status != store.DeviceCodeStatusPending {
			t.Errorf("strike #%d: Status = %v, want Pending (lockout fires only on the ceiling)", i, got.Status)
		}
	}

	// Strike 5: lockout transition. The helper still returns
	// (false, nil) for the failed match; the side effect is on the
	// substore.
	matched, err := devicecodekit.VerifyUserCode(context.Background(), deps, deviceCode, "WRONG5")
	if err != nil {
		t.Fatalf("strike #5: VerifyUserCode err = %v", err)
	}
	if matched {
		t.Errorf("strike #5: matched = true on mismatched submission")
	}
	got, err := p.tk.Store.DeviceCodes().FindByDeviceCode(context.Background(), deviceCode)
	if err != nil {
		t.Fatalf("after lockout: FindByDeviceCode: %v", err)
	}
	if got.Status != store.DeviceCodeStatusDenied {
		t.Errorf("after lockout: Status = %v, want Denied", got.Status)
	}
	if got.DenyReason != devicecodekit.DenyReasonUserCodeLockout {
		t.Errorf("after lockout: DenyReason = %q, want %q",
			got.DenyReason, devicecodekit.DenyReasonUserCodeLockout)
	}

	// Strike 6+: subsequent submissions short-circuit on ErrAlreadyDecided
	// even when the embedder presents the canonical user_code, so a
	// probing attacker cannot generate audit noise past the ceiling.
	matched, err = devicecodekit.VerifyUserCode(context.Background(), deps, deviceCode, correct)
	if !errors.Is(err, devicecodekit.ErrAlreadyDecided) {
		t.Fatalf("post-lockout submission: err = %v, want ErrAlreadyDecided", err)
	}
	if matched {
		t.Errorf("post-lockout submission: matched = true on a Denied record")
	}
	postLockoutRec, err := p.tk.Store.DeviceCodes().FindByDeviceCode(context.Background(), deviceCode)
	if err != nil {
		t.Fatalf("post-lockout FindByDeviceCode: %v", err)
	}
	if postLockoutRec.UserCodeStrikes != got.UserCodeStrikes {
		t.Errorf("post-lockout Strikes = %d, want %d (no further increments)",
			postLockoutRec.UserCodeStrikes, got.UserCodeStrikes)
	}

	// Wire posture on the polling channel: a /token poll for the
	// locked-out device_code returns access_denied. The substore's
	// Denied → access_denied mapping is the existing piece of
	// machinery the gate relies on; this assertion pins that the
	// gate's audit-only side effect did not regress the wire shape.
	status, body := p.tokenForm(t, url.Values{
		"grant_type":  {devURNDeviceCode},
		"device_code": {deviceCode},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("post-lockout /token: status=%d want 400 body=%v", status, body)
	}
	expectError(t, body, "access_denied")
}

// TestScenario_DEV_101_RevokeEmitsAuditAndTransitions pins the public
// revoke helper (op/devicecodekit.Revoke). The helper transitions a
// Pending record to Denied with the supplied reason, cascade-revokes
// every access token issued from that device_code (its ID is the
// GrantID on each token), the next /token poll returns access_denied,
// and a second revoke call safely retries the idempotent cascade.
//
// Spec: RFC 8628 §3.5, OAuth 2.0 user-trust posture.
func TestScenario_DEV_101_RevokeEmitsAuditAndTransitions(t *testing.T) {
	t.Parallel()
	p := newDevProvider(t, []string{"openid"})

	deviceCode := p.issueDeviceCode(t, "openid")
	reg := p.tk.Store.AccessTokens()
	deps := &devicecodekit.Deps{
		DeviceCodes:        p.tk.Store.DeviceCodes(),
		AccessTokens:       reg,
		RevocationStrategy: store.RevocationStrategyJTIRegistry,
	}

	// An access token whose GrantID is the device_code's ID stands in
	// for one issued from this device authorization; the cascade must
	// retire it when the authorization is revoked.
	now := time.Now()
	if err := reg.Register(context.Background(), store.AccessTokenRecord{
		JTI:       "dev-101-at",
		GrantID:   deviceCode,
		ClientID:  "client-1",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Register access token: %v", err)
	}

	if err := devicecodekit.Revoke(context.Background(), deps, deviceCode, devicecodekit.DenyReasonUserRevokedDevice); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	if at, err := reg.Find(context.Background(), "dev-101-at"); err != nil {
		t.Fatalf("Find access token after revoke: %v", err)
	} else if at == nil || !at.Revoked {
		t.Errorf("device_code access token not cascade-revoked: %+v", at)
	}
	rec, err := p.tk.Store.DeviceCodes().FindByDeviceCode(context.Background(), deviceCode)
	if err != nil {
		t.Fatalf("FindByDeviceCode after revoke: %v", err)
	}
	if rec.Status != store.DeviceCodeStatusDenied {
		t.Errorf("Status = %v, want Denied after revoke", rec.Status)
	}
	if rec.DenyReason != devicecodekit.DenyReasonUserRevokedDevice {
		t.Errorf("DenyReason = %q, want %q",
			rec.DenyReason, devicecodekit.DenyReasonUserRevokedDevice)
	}

	// Wire posture: /token poll returns access_denied because the
	// substore now reports the record as Denied.
	status, body := p.tokenForm(t, url.Values{
		"grant_type":  {devURNDeviceCode},
		"device_code": {deviceCode},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("post-revoke /token: status=%d want 400 body=%v", status, body)
	}
	expectError(t, body, "access_denied")

	// Idempotency: a second revoke retries the cascade and succeeds.
	if err := devicecodekit.Revoke(context.Background(), deps, deviceCode, devicecodekit.DenyReasonUserRevokedDevice); err != nil {
		t.Errorf("second Revoke: %v", err)
	}
}
