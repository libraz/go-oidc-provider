package scenarios_test

// Catalog: test/scenarios/catalog/registration_management.yaml (RM-NNN)
// Spec:
//   - RFC 7592 — OAuth 2.0 Dynamic Client Registration Management Protocol
//   - RFC 7591 — Dynamic Client Registration (metadata)
//   - RFC 6750 — Bearer Token Usage
//   - OpenID Connect Core 1.0 §16

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// rmRegistered bundles the result of a successful POST /register so
// management tests can drive GET / PUT / DELETE without re-registering
// every time. registrationClientURI is rewritten to the testkit server
// URL (the OP advertises the registration_client_uri rooted at the
// configured Issuer, which the test client cannot reach over the
// network).
type rmRegistered struct {
	clientID                string
	clientIDIssuedAt        int64
	clientSecret            string
	registrationAccessToken string
	registrationClientURI   string
	body                    map[string]any
}

// rmRegisterClient issues a POST /register against the testkit's DCR
// endpoint and returns the parsed response. The provider MUST be
// constructed with op.WithDynamicRegistration; the helper mints a
// fresh IAT through the public op.Provider.IssueInitialAccessToken
// API for every call.
func rmRegisterClient(t *testing.T, tk *testkit.Provider, body map[string]any) rmRegistered {
	t.Helper()
	if body == nil {
		body = map[string]any{
			"redirect_uris": []string{"https://rp.test.invalid/callback"},
		}
	}
	issued, err := tk.OP.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{})
	if err != nil {
		t.Fatalf("IssueInitialAccessToken: %v", err)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal body: %v", err)
	}
	endpoint := tk.Server.URL + "/oidc/register"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+issued.Value)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /oidc/register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /oidc/register: status=%d want 201 body=%s", resp.StatusCode, raw)
	}
	got := rmDecodeBody(t, resp)
	out := rmRegistered{body: got}
	out.clientID, _ = got["client_id"].(string)
	if issuedAt, ok := got["client_id_issued_at"].(float64); ok {
		out.clientIDIssuedAt = int64(issuedAt)
	}
	out.clientSecret, _ = got["client_secret"].(string)
	out.registrationAccessToken, _ = got["registration_access_token"].(string)
	if out.clientID == "" || out.registrationAccessToken == "" {
		t.Fatalf("rmRegisterClient: malformed response %+v", got)
	}
	out.registrationClientURI = endpoint + "/" + out.clientID
	return out
}

// rmManage issues a method+JSON request against /register/{client_id}.
// body=nil means no body; bearer="" means no Authorization header.
func rmManage(t *testing.T, tk *testkit.Provider, method, path, bearer string, body any) *http.Response {
	t.Helper()
	var reader io.Reader = http.NoBody
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, path, reader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do %s %s: %v", method, path, err)
	}
	return resp
}

// rmDecodeBody unmarshals the response body as JSON. Empty bodies
// return an empty map.
func rmDecodeBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("Unmarshal(%s): %v", raw, err)
	}
	return out
}

// rmAssertNoStore checks the no-store / no-cache headers RFC 7591 §3.2
// requires on every registration endpoint response (success or error).
func rmAssertNoStore(t *testing.T, resp *http.Response) {
	t.Helper()
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control=%q want no-store", got)
	}
	if got := resp.Header.Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma=%q want no-cache", got)
	}
}

// TestScenario_RM_FF_01_RequiresDCREnabled documents v1.0's bundled
// registration management gating: there is no separate
// registrationManagement toggle, so the upstream error path "registration
// management enabled without registration" has no equivalent.
//
// Spec: RFC 7592 §1; v1.0 design (mountRegistrationEndpoint mounts
// management routes alongside POST /register).
func TestScenario_RM_FF_01_RequiresDCREnabled(t *testing.T) {
	t.Parallel()
	t.Skip("RM-FF-01 is out of scope: v1.0 has no separate registrationManagement toggle.")
}

// TestScenario_RM_FF_02_RoutesHiddenWhenDisabled checks that without
// op.WithDynamicRegistration the management routes are not mounted;
// PUT /register/{client_id} returns 404.
//
// Spec: RFC 7592 §3.
func TestScenario_RM_FF_02_RoutesHiddenWhenDisabled(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	resp := rmManage(t, tk, http.MethodPut, tk.Server.URL+"/oidc/register/anyone", "irrelevant", map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 404 body=%s", resp.StatusCode, raw)
	}
}

// TestScenario_RM_PUT_01_RequiresBearerRAT checks PUT
// /register/{client_id} without an Authorization header is rejected
// with 401 invalid_token "registration access token is required".
//
// Spec: RFC 7592 §2.2 / RFC 6750 §3.
func TestScenario_RM_PUT_01_RequiresBearerRAT(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	created := rmRegisterClient(t, tk, nil)

	resp := rmManage(t, tk, http.MethodPut, created.registrationClientURI, "", map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	body := rmDecodeBody(t, resp)
	if got, _ := body["error"].(string); got != "invalid_token" {
		t.Errorf("error=%q want invalid_token", got)
	}
	if got, _ := body["error_description"].(string); got != "registration access token is required" {
		t.Errorf("error_description=%q want %q", got, "registration access token is required")
	}
	if !strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate=%q must include invalid_token challenge", resp.Header.Get("WWW-Authenticate"))
	}
}

// TestScenario_RM_PUT_02_InvalidRATIs401 checks that presenting a
// syntactically valid but unrecognised RAT yields 401 invalid_token
// with description "registration access token is invalid".
//
// Spec: RFC 7592 §2.2.
func TestScenario_RM_PUT_02_InvalidRATIs401(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	created := rmRegisterClient(t, tk, nil)

	resp := rmManage(t, tk, http.MethodPut, created.registrationClientURI, "this-is-not-the-rat", map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	body := rmDecodeBody(t, resp)
	if got, _ := body["error"].(string); got != "invalid_token" {
		t.Errorf("error=%q want invalid_token", got)
	}
	if got, _ := body["error_description"].(string); got != "registration access token is invalid" {
		t.Errorf("error_description=%q want %q", got, "registration access token is invalid")
	}
}

// TestScenario_RM_PUT_03_SuccessReturns200NoStore checks that a valid
// PUT returns 200 OK with Cache-Control: no-store and Content-Type:
// application/json.
//
// Spec: RFC 7592 §2.2 / §3.2.
func TestScenario_RM_PUT_03_SuccessReturns200NoStore(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	created := rmRegisterClient(t, tk, nil)

	resp := rmManage(t, tk, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb-new"},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type=%q want application/json", got)
	}
	rmAssertNoStore(t, resp)
}

// TestScenario_RM_PUT_04_ResponseBodyShape verifies the RFC 7591 §3.2.1
// response envelope on a successful PUT — client_id, client_id_issued_at,
// registration_client_uri, and registration_access_token are present;
// client_secret is present for confidential clients.
//
// Spec: RFC 7591 §3.2.1 / RFC 7592 §2.2.
func TestScenario_RM_PUT_04_ResponseBodyShape(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	created := rmRegisterClient(t, tk, map[string]any{
		"redirect_uris":              []string{"https://rp.test.invalid/cb"},
		"token_endpoint_auth_method": "client_secret_basic",
	})

	resp := rmManage(t, tk, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, map[string]any{
		"redirect_uris":              []string{"https://rp.test.invalid/cb"},
		"token_endpoint_auth_method": "client_secret_basic",
		"client_name":                "Renamed Client",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body := rmDecodeBody(t, resp)
	if got, _ := body["client_id"].(string); got != created.clientID {
		t.Errorf("client_id=%q want %q", got, created.clientID)
	}
	if issuedAt, _ := body["client_id_issued_at"].(float64); int64(issuedAt) != created.clientIDIssuedAt {
		t.Errorf("client_id_issued_at=%v want %d", body["client_id_issued_at"], created.clientIDIssuedAt)
	}
	uri, _ := body["registration_client_uri"].(string)
	if !strings.HasSuffix(uri, "/oidc/register/"+created.clientID) {
		t.Errorf("registration_client_uri=%q must end with /oidc/register/%s", uri, created.clientID)
	}
	rat, _ := body["registration_access_token"].(string)
	if rat == "" {
		t.Error("registration_access_token missing from PUT response")
	}
	if _, ok := body["client_secret_expires_at"]; !ok {
		t.Error("client_secret_expires_at must be present in PUT response")
	}
}

// TestScenario_RM_PUT_05_BodyMustNotIncludeRAT checks that a PUT body
// carrying registration_access_token is rejected with 400
// invalid_request.
//
// Spec: RFC 7592 §2.2.
func TestScenario_RM_PUT_05_BodyMustNotIncludeRAT(t *testing.T) {
	t.Parallel()
	rmAssertForbiddenField(t, "registration_access_token", "rat-value",
		"request MUST NOT include the registration_access_token field")
}

// TestScenario_RM_PUT_06_BodyMustNotIncludeRegistrationClientURI checks
// that a PUT body carrying registration_client_uri is rejected.
//
// Spec: RFC 7592 §2.2.
func TestScenario_RM_PUT_06_BodyMustNotIncludeRegistrationClientURI(t *testing.T) {
	t.Parallel()
	rmAssertForbiddenField(t, "registration_client_uri", "https://op.example/register/foo",
		"request MUST NOT include the registration_client_uri field")
}

// TestScenario_RM_PUT_07_BodyMustNotIncludeSecretExpiresAt checks that
// a PUT body carrying client_secret_expires_at is rejected.
//
// Spec: RFC 7592 §2.2.
func TestScenario_RM_PUT_07_BodyMustNotIncludeSecretExpiresAt(t *testing.T) {
	t.Parallel()
	rmAssertForbiddenField(t, "client_secret_expires_at", float64(0),
		"request MUST NOT include the client_secret_expires_at field")
}

// TestScenario_RM_PUT_08_BodyMustNotIncludeClientIDIssuedAt checks that
// a PUT body carrying client_id_issued_at is rejected.
//
// Spec: RFC 7592 §2.2.
func TestScenario_RM_PUT_08_BodyMustNotIncludeClientIDIssuedAt(t *testing.T) {
	t.Parallel()
	rmAssertForbiddenField(t, "client_id_issued_at", float64(123),
		"request MUST NOT include the client_id_issued_at field")
}

// rmAssertForbiddenField is the shared driver for RM-PUT-05..08. It
// registers a fresh DCR client, sends a PUT body with the offending
// field, and asserts the wire envelope.
func rmAssertForbiddenField(t *testing.T, field string, value any, wantDescription string) {
	t.Helper()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	created := rmRegisterClient(t, tk, nil)

	body := map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
		field:           value,
	}
	resp := rmManage(t, tk, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	got := rmDecodeBody(t, resp)
	if e, _ := got["error"].(string); e != "invalid_request" {
		t.Errorf("error=%q want invalid_request", e)
	}
	if d, _ := got["error_description"].(string); d != wantDescription {
		t.Errorf("error_description=%q want %q", d, wantDescription)
	}
}

// TestScenario_RM_PUT_09_OmittedPropertyIsDeleted checks that omitting
// a previously-set optional property on PUT removes it from the
// persisted client and the response body.
//
// Spec: RFC 7592 §2.2.
func TestScenario_RM_PUT_09_OmittedPropertyIsDeleted(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	created := rmRegisterClient(t, tk, map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
		"client_name":   "Original Name",
	})

	resp := rmManage(t, tk, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body := rmDecodeBody(t, resp)
	if got, ok := body["client_name"]; ok {
		t.Errorf("client_name=%v want absent on omission", got)
	}
}

// TestScenario_RM_PUT_10_NullSecretRejected checks that sending
// client_secret as null on a confidential client yields 400
// invalid_request "provided client_secret does not match the
// authenticated client's one".
//
// Spec: RFC 7592 §2.2.
func TestScenario_RM_PUT_10_NullSecretRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	created := rmRegisterClient(t, tk, map[string]any{
		"redirect_uris":              []string{"https://rp.test.invalid/cb"},
		"token_endpoint_auth_method": "client_secret_basic",
	})

	resp := rmManage(t, tk, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, map[string]any{
		"redirect_uris":              []string{"https://rp.test.invalid/cb"},
		"token_endpoint_auth_method": "client_secret_basic",
		"client_secret":              nil,
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	got := rmDecodeBody(t, resp)
	if e, _ := got["error"].(string); e != "invalid_request" {
		t.Errorf("error=%q want invalid_request", e)
	}
	if d, _ := got["error_description"].(string); d != "provided client_secret does not match the authenticated client's one" {
		t.Errorf("error_description=%q want %q", d, "provided client_secret does not match the authenticated client's one")
	}
}

// TestScenario_RM_PUT_11_AuthMethodSwitchMintsSecret checks that
// switching token_endpoint_auth_method from "none" to
// "client_secret_basic" causes the OP to mint a fresh client_secret
// and include it in the response body.
//
// Spec: RFC 7592 §2.2 / OIDC Core §16.
func TestScenario_RM_PUT_11_AuthMethodSwitchMintsSecret(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	created := rmRegisterClient(t, tk, map[string]any{
		"redirect_uris":              []string{"https://rp.test.invalid/cb"},
		"token_endpoint_auth_method": "none",
	})
	if created.clientSecret != "" {
		t.Fatalf("public client must not have a client_secret on POST, got %q", created.clientSecret)
	}

	resp := rmManage(t, tk, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, map[string]any{
		"redirect_uris":              []string{"https://rp.test.invalid/cb"},
		"token_endpoint_auth_method": "client_secret_basic",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body := rmDecodeBody(t, resp)
	secret, _ := body["client_secret"].(string)
	if secret == "" {
		t.Error("PUT response must include a fresh client_secret on auth-method switch to confidential")
	}

	persisted, err := tk.Store.GetClient(context.Background(), created.clientID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if persisted.SecretHash == "" {
		t.Error("persisted client must carry a SecretHash after auth-method switch")
	}
	if persisted.PublicClient {
		t.Error("persisted client must be confidential after auth-method switch")
	}
}

// TestScenario_RM_PUT_12_RATRotationDestroysOld checks that PUT mints
// a fresh RAT and the previous RAT no longer authenticates.
//
// Spec: RFC 7592 §3.
func TestScenario_RM_PUT_12_RATRotationDestroysOld(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	created := rmRegisterClient(t, tk, nil)

	resp := rmManage(t, tk, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body := rmDecodeBody(t, resp)
	newRAT, _ := body["registration_access_token"].(string)
	if newRAT == "" {
		t.Fatal("PUT response must include a fresh RAT")
	}
	if newRAT == created.registrationAccessToken {
		t.Fatal("PUT must rotate the RAT, got the same value")
	}

	stale := rmManage(t, tk, http.MethodGet, created.registrationClientURI, created.registrationAccessToken, nil)
	defer func() { _ = stale.Body.Close() }()
	if stale.StatusCode != http.StatusUnauthorized {
		t.Errorf("stale RAT GET status=%d want 401", stale.StatusCode)
	}
	fresh := rmManage(t, tk, http.MethodGet, created.registrationClientURI, newRAT, nil)
	defer func() { _ = fresh.Body.Close() }()
	if fresh.StatusCode != http.StatusOK {
		t.Errorf("fresh RAT GET status=%d want 200", fresh.StatusCode)
	}
}

// TestScenario_RM_PUT_13_EntitiesCarryRotationPair documents that
// v1.0 has no upstream-style ctx.oidc.entities surface; rotation
// observability lives in the audit stream instead (see RM-EVT-01).
//
// Spec: OP design (no entities surface in v1.0).
func TestScenario_RM_PUT_13_EntitiesCarryRotationPair(t *testing.T) {
	t.Parallel()
	t.Skip("RM-PUT-13 is out of scope: v1.0 does not expose ctx.oidc.entities.")
}

// TestScenario_RM_PUT_14_UpdateAuditEmitted checks that a successful
// PUT emits the dcr.client.metadata_updated audit event carrying the
// updated client_id.
//
// Spec: OP audit catalogue (op.AuditDCRClientMetadataUpdated).
func TestScenario_RM_PUT_14_UpdateAuditEmitted(t *testing.T) {
	t.Parallel()

	audit := scenariokit.NewAuditCapture()
	tk := testkit.NewProvider(t,
		testkit.WithOptions(
			op.WithDynamicRegistration(op.RegistrationOption{}),
			op.WithAuditLogger(audit.Logger()),
		),
	)
	created := rmRegisterClient(t, tk, nil)

	resp := rmManage(t, tk, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb-edit"},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}

	events := audit.EventsByName(string(op.AuditDCRClientMetadataUpdated))
	if len(events) != 1 {
		t.Fatalf("dcr.client.metadata_updated emissions=%d want 1 (events=%v)", len(events), audit.Events())
	}
}

// TestScenario_RM_PUT_15_StaticClientForbidden checks that a PUT
// against a static (non-DCR) client is rejected with 401
// invalid_token "registration access token is invalid". v1.0 enforces
// "static clients cannot be managed" through the absence of a RAT
// row, not through a 403 invalid_request.
//
// Spec: RFC 7592 §2; v1.0 design (verifyRAT requires Source=Dynamic).
func TestScenario_RM_PUT_15_StaticClientForbidden(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	staticClient := tk.RegisterClient(t, testkit.ClientFixture{
		ID:           "rm-static-put",
		RedirectURIs: []string{"https://rp.test.invalid/static-cb"},
		PublicClient: true,
	})
	path := tk.Server.URL + "/oidc/register/" + staticClient.ID

	resp := rmManage(t, tk, http.MethodPut, path, "any-rat-value", map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/static-cb"},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	body := rmDecodeBody(t, resp)
	if e, _ := body["error"].(string); e != "invalid_token" {
		t.Errorf("error=%q want invalid_token", e)
	}
	if d, _ := body["error_description"].(string); d != "registration access token is invalid" {
		t.Errorf("error_description=%q want %q", d, "registration access token is invalid")
	}
}

// TestScenario_RM_PUT_16_ValidationFailsAsClientMetadata checks that
// metadata-validation failures on PUT (e.g. an unsupported
// token_endpoint_auth_method) surface as 400
// invalid_client_metadata, matching the POST /register error code.
//
// Spec: RFC 7591 §3.2.2.
func TestScenario_RM_PUT_16_ValidationFailsAsClientMetadata(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	created := rmRegisterClient(t, tk, nil)

	// "client_secret_jwt" is not in v1.0's admitted auth-method set.
	resp := rmManage(t, tk, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, map[string]any{
		"redirect_uris":              []string{"https://rp.test.invalid/cb"},
		"token_endpoint_auth_method": "client_secret_jwt",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	body := rmDecodeBody(t, resp)
	if e, _ := body["error"].(string); e != "invalid_client_metadata" {
		t.Errorf("error=%q want invalid_client_metadata", e)
	}
}

// TestScenario_RM_PUT_17_ClientIDMismatchRejected checks that sending
// a body whose client_id disagrees with the path {client_id} yields
// 400 invalid_request "client_id is immutable".
//
// Spec: RFC 7592 §2.2.
func TestScenario_RM_PUT_17_ClientIDMismatchRejected(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	created := rmRegisterClient(t, tk, nil)

	resp := rmManage(t, tk, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
		"client_id":     "trying-to-rename",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	body := rmDecodeBody(t, resp)
	if e, _ := body["error"].(string); e != "invalid_request" {
		t.Errorf("error=%q want invalid_request", e)
	}
	if d, _ := body["error_description"].(string); d != "client_id is immutable" {
		t.Errorf("error_description=%q want %q", d, "client_id is immutable")
	}
}

// TestScenario_RM_DEL_01_RequiresRAT checks DELETE
// /register/{client_id} without RAT yields 401 invalid_token
// "registration access token is required", and with a wrong RAT
// "registration access token is invalid".
//
// Spec: RFC 7592 §2.3.
func TestScenario_RM_DEL_01_RequiresRAT(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	created := rmRegisterClient(t, tk, nil)

	noAuth := rmManage(t, tk, http.MethodDelete, created.registrationClientURI, "", nil)
	defer func() { _ = noAuth.Body.Close() }()
	if noAuth.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(noAuth.Body)
		t.Fatalf("no-auth status=%d want 401 body=%s", noAuth.StatusCode, raw)
	}
	body := rmDecodeBody(t, noAuth)
	if e, _ := body["error"].(string); e != "invalid_token" {
		t.Errorf("no-auth error=%q want invalid_token", e)
	}
	if d, _ := body["error_description"].(string); d != "registration access token is required" {
		t.Errorf("no-auth error_description=%q want %q", d, "registration access token is required")
	}

	bogus := rmManage(t, tk, http.MethodDelete, created.registrationClientURI, "totally-bogus", nil)
	defer func() { _ = bogus.Body.Close() }()
	if bogus.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(bogus.Body)
		t.Fatalf("bogus-rat status=%d want 401 body=%s", bogus.StatusCode, raw)
	}
	body = rmDecodeBody(t, bogus)
	if d, _ := body["error_description"].(string); d != "registration access token is invalid" {
		t.Errorf("bogus-rat error_description=%q want %q", d, "registration access token is invalid")
	}
}

// TestScenario_RM_DEL_02_SuccessReturns204 checks a successful DELETE
// returns 204 No Content with empty body and the no-store cache
// headers.
//
// Spec: RFC 7592 §2.3.
func TestScenario_RM_DEL_02_SuccessReturns204(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	created := rmRegisterClient(t, tk, nil)

	resp := rmManage(t, tk, http.MethodDelete, created.registrationClientURI, created.registrationAccessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 204 body=%s", resp.StatusCode, raw)
	}
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) != 0 {
		t.Errorf("DELETE body must be empty, got %q", raw)
	}
	rmAssertNoStore(t, resp)
}

// TestScenario_RM_DEL_03_RATDestroyedOnSuccess checks that the RAT
// row is destroyed on DELETE; replaying the same RAT against any
// management endpoint yields 401 invalid_token.
//
// Spec: RFC 7592 §2.3.
func TestScenario_RM_DEL_03_RATDestroyedOnSuccess(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	created := rmRegisterClient(t, tk, nil)

	del := rmManage(t, tk, http.MethodDelete, created.registrationClientURI, created.registrationAccessToken, nil)
	defer func() { _ = del.Body.Close() }()
	if del.StatusCode != http.StatusNoContent {
		raw, _ := io.ReadAll(del.Body)
		t.Fatalf("DELETE status=%d want 204 body=%s", del.StatusCode, raw)
	}

	if _, err := tk.Store.RegistrationAccessTokens().GetByClientID(context.Background(), created.clientID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("RAT lookup post-delete: want ErrNotFound, got %v", err)
	}

	// Replay against GET — same RAT must no longer authenticate.
	replay := rmManage(t, tk, http.MethodGet, created.registrationClientURI, created.registrationAccessToken, nil)
	defer func() { _ = replay.Body.Close() }()
	if replay.StatusCode != http.StatusUnauthorized {
		t.Errorf("replay GET status=%d want 401", replay.StatusCode)
	}
}

// TestScenario_RM_DEL_04_AssociatedTokensInvalidated checks that the
// client record is destroyed and the OnClientDeleted cascade hook is
// invoked with the deleted client_id. v1.0's store interfaces do not
// publish a "by client" enumeration, so the library does NOT cascade
// access-token / refresh-token / session destruction itself —
// embedders maintain those indexes through the hook.
//
// Spec: RFC 7592 §2.3 / OIDC Core §16.21; v1.0 design
// (RegistrationOption.OnClientDeleted).
func TestScenario_RM_DEL_04_AssociatedTokensInvalidated(t *testing.T) {
	t.Parallel()

	var hookCalls atomic.Int32
	var seenClientID atomic.Value
	hook := func(_ context.Context, clientID string) error {
		hookCalls.Add(1)
		seenClientID.Store(clientID)
		return nil
	}

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{
			OnClientDeleted: hook,
		})),
	)
	created := rmRegisterClient(t, tk, nil)

	resp := rmManage(t, tk, http.MethodDelete, created.registrationClientURI, created.registrationAccessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 204 body=%s", resp.StatusCode, raw)
	}

	if _, err := tk.Store.GetClient(context.Background(), created.clientID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("client lookup post-delete: want ErrNotFound, got %v", err)
	}
	if got := hookCalls.Load(); got != 1 {
		t.Fatalf("OnClientDeleted call count=%d want 1", got)
	}
	if got, _ := seenClientID.Load().(string); got != created.clientID {
		t.Errorf("OnClientDeleted client_id=%q want %q", got, created.clientID)
	}
}

// TestScenario_RM_DEL_05_StaticClientForbidden checks that a DELETE
// against a static (non-DCR) client is rejected with 401
// invalid_token, on the same RAT-absence gate as RM-PUT-15.
//
// Spec: RFC 7592 §2; v1.0 design.
func TestScenario_RM_DEL_05_StaticClientForbidden(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	staticClient := tk.RegisterClient(t, testkit.ClientFixture{
		ID:           "rm-static-del",
		RedirectURIs: []string{"https://rp.test.invalid/static-cb"},
		PublicClient: true,
	})
	path := tk.Server.URL + "/oidc/register/" + staticClient.ID

	resp := rmManage(t, tk, http.MethodDelete, path, "any-rat-value", nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	body := rmDecodeBody(t, resp)
	if e, _ := body["error"].(string); e != "invalid_token" {
		t.Errorf("error=%q want invalid_token", e)
	}
	if d, _ := body["error_description"].(string); d != "registration access token is invalid" {
		t.Errorf("error_description=%q want %q", d, "registration access token is invalid")
	}

	// The static client must still be present after the failed delete.
	if _, err := tk.Store.GetClient(context.Background(), staticClient.ID); err != nil {
		t.Errorf("static client lookup after rejected DELETE: %v", err)
	}
}

// TestScenario_RM_DEL_06_DeleteAuditEmitted checks that DELETE emits
// the dcr.client.deleted audit event carrying the deleted client_id.
//
// Spec: OP audit catalogue (op.AuditDCRClientDeleted).
func TestScenario_RM_DEL_06_DeleteAuditEmitted(t *testing.T) {
	t.Parallel()

	audit := scenariokit.NewAuditCapture()
	tk := testkit.NewProvider(t,
		testkit.WithOptions(
			op.WithDynamicRegistration(op.RegistrationOption{}),
			op.WithAuditLogger(audit.Logger()),
		),
	)
	created := rmRegisterClient(t, tk, nil)

	resp := rmManage(t, tk, http.MethodDelete, created.registrationClientURI, created.registrationAccessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 204 body=%s", resp.StatusCode, raw)
	}

	events := audit.EventsByName(string(op.AuditDCRClientDeleted))
	if len(events) != 1 {
		t.Fatalf("dcr.client.deleted emissions=%d want 1", len(events))
	}
}

// TestScenario_RM_CTX_01_HandlersPopulateEntities documents that
// v1.0 has no upstream-style ctx.oidc.entities surface. The internal
// request-scoped state (resolved client + RAT record) is not
// wire-visible.
//
// Spec: OP design (no entities surface).
func TestScenario_RM_CTX_01_HandlersPopulateEntities(t *testing.T) {
	t.Parallel()
	t.Skip("RM-CTX-01 is out of scope: v1.0 does not expose ctx.oidc.entities.")
}

// TestScenario_RM_EVT_01_RotationEmitsSavedAndDestroyed checks the
// v1.0 rotation observability surface: a successful PUT emits the
// dcr.client.metadata_updated audit event, and the previous RAT
// stops authenticating (the verifier records dcr.rat.invalid on the
// follow-up stale-RAT use).
//
// Spec: OP audit catalogue.
func TestScenario_RM_EVT_01_RotationEmitsSavedAndDestroyed(t *testing.T) {
	t.Parallel()

	audit := scenariokit.NewAuditCapture()
	tk := testkit.NewProvider(t,
		testkit.WithOptions(
			op.WithDynamicRegistration(op.RegistrationOption{}),
			op.WithAuditLogger(audit.Logger()),
		),
	)
	created := rmRegisterClient(t, tk, nil)

	resp := rmManage(t, tk, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb-rotated"},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("PUT status=%d want 200 body=%s", resp.StatusCode, raw)
	}

	updated := audit.EventsByName(string(op.AuditDCRClientMetadataUpdated))
	if len(updated) != 1 {
		t.Fatalf("dcr.client.metadata_updated emissions=%d want 1", len(updated))
	}

	// Drive the previous RAT against GET to surface the rotation
	// destroy half: the verifier emits dcr.rat.invalid on hash
	// mismatch.
	stale := rmManage(t, tk, http.MethodGet, created.registrationClientURI, created.registrationAccessToken, nil)
	defer func() { _ = stale.Body.Close() }()
	if stale.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stale RAT GET status=%d want 401", stale.StatusCode)
	}
	invalid := audit.EventsByName(string(op.AuditDCRRATInvalid))
	if len(invalid) < 1 {
		t.Fatalf("dcr.rat.invalid emissions=%d want >=1 after stale RAT use", len(invalid))
	}
}

// TestScenario_RM_RAT_01_CrossClientRATRejectedNotDestroyed checks that
// presenting client A's RAT against client B's
// /register/{client_id} URL yields 401 invalid_token. The
// constant-time RAT verifier hashes the bearer and compares to the
// stored hash for client B; the mismatch path returns the canonical
// invalid_token envelope, and the leaked-RAT signal stays at the
// audit layer (dcr.rat.invalid, hash_mismatch).
//
// The name states the negative half deliberately. Destroying a RAT the
// moment it is presented at the wrong URL hands any party who learns it
// a one-request way to lock the legitimate owner out of its own
// registration, so this OP rejects the request and keeps the
// credential. Naming the test for an auto-destroy it does not perform
// would leave the assertion below reading as a bug.
//
// Spec: RFC 7592 §2 + security hardening.
func TestScenario_RM_RAT_01_CrossClientRATRejectedNotDestroyed(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	clientA := rmRegisterClient(t, tk, nil)
	clientB := rmRegisterClient(t, tk, nil)

	// Probe clientB's URL with clientA's RAT.
	resp := rmManage(t, tk, http.MethodGet, clientB.registrationClientURI, clientA.registrationAccessToken, nil)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("cross-client status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	body := rmDecodeBody(t, resp)
	if e, _ := body["error"].(string); e != "invalid_token" {
		t.Errorf("error=%q want invalid_token", e)
	}

	// Defensive: clientA's RAT must still authenticate against its own URL —
	// v1.0 deliberately does NOT auto-destroy a leaked RAT on a single
	// cross-client probe (the constant-time mismatch leaks no signal).
	own := rmManage(t, tk, http.MethodGet, clientA.registrationClientURI, clientA.registrationAccessToken, nil)
	defer func() { _ = own.Body.Close() }()
	if own.StatusCode != http.StatusOK {
		t.Errorf("clientA self GET after cross-client probe: status=%d want 200", own.StatusCode)
	}
}

// TestScenario_RM_RAT_02_RATPersistedWithUniqueJTI checks that the
// RAT is persisted through the public RegistrationAccessTokenStore.
// v1.0's RAT record does not surface a separate JTI on the public
// store contract; the persistence guarantee asserted here is the
// existence of a stored RAT row for the client and a stable
// CreatedAt timestamp.
//
// Spec: RFC 7592 §2 / v1.0 store contract.
func TestScenario_RM_RAT_02_RATPersistedWithUniqueJTI(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	created := rmRegisterClient(t, tk, nil)

	rec, err := tk.Store.RegistrationAccessTokens().GetByClientID(context.Background(), created.clientID)
	if err != nil {
		t.Fatalf("RegistrationAccessTokens.GetByClientID: %v", err)
	}
	if rec.ClientID != created.clientID {
		t.Errorf("rec.ClientID=%q want %q", rec.ClientID, created.clientID)
	}
	if rec.HashedValue == "" {
		t.Error("rec.HashedValue must be present")
	}
	if rec.CreatedAt.IsZero() {
		t.Error("rec.CreatedAt must be set")
	}
}

// TestScenario_RM_RAT_03_RATIsOpaqueToken checks that the RAT value
// returned in the registration response is an opaque OP-internal
// token (base64url, no padding) and that the persisted record stores
// only the SHA-256 hash — the raw RAT cannot be recovered from the
// store.
//
// Spec: RFC 6750 §2.1.
func TestScenario_RM_RAT_03_RATIsOpaqueToken(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithOptions(op.WithDynamicRegistration(op.RegistrationOption{})),
	)
	created := rmRegisterClient(t, tk, nil)

	rat := created.registrationAccessToken
	if rat == "" {
		t.Fatal("RAT must be present")
	}
	// base64url no-padding charset: A-Z a-z 0-9 - _
	for _, r := range rat {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			t.Errorf("RAT contains non-base64url character %q", r)
		}
	}
	// JWT shape would carry exactly two '.' separators.
	if strings.Count(rat, ".") != 0 {
		t.Errorf("RAT %q must be opaque (no JWT-style dots)", rat)
	}

	// The persisted record must NOT echo the raw RAT.
	rec, err := tk.Store.RegistrationAccessTokens().GetByClientID(context.Background(), created.clientID)
	if err != nil {
		t.Fatalf("GetByClientID: %v", err)
	}
	if rec.HashedValue == rat {
		t.Error("persisted HashedValue must not equal the raw RAT")
	}
	if strings.Contains(rec.HashedValue, rat) {
		t.Error("persisted HashedValue must not embed the raw RAT")
	}
}

// TestScenario_RM_RAT_04_RotationInheritsPolicies documents that
// v1.0 does not surface a per-RAT policy bundle on the public store
// contract. Rotation overwrites the RAT row with a fresh ClientID +
// HashedValue + CreatedAt triple; there is no "policy inheritance"
// surface to assert against.
//
// Spec: OP design (no per-RAT policy surface in v1.0).
func TestScenario_RM_RAT_04_RotationInheritsPolicies(t *testing.T) {
	t.Parallel()
	t.Skip("RM-RAT-04 is out of scope: v1.0's RegistrationAccessToken has no public policy surface.")
}
