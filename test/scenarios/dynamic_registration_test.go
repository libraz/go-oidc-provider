package scenarios_test

// Catalog: test/scenarios/catalog/dynamic_registration.yaml (DCR-NNN)
// Spec:
//   - RFC 7591 — OAuth 2.0 Dynamic Client Registration Protocol
//   - OpenID Connect Dynamic Client Registration 1.0
//   - RFC 6749 §2 — Client Types
//   - RFC 8414 §2 — Authorization Server Metadata (registration_endpoint)

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// dcrFixture bundles a [testkit.Provider] with Dynamic Client
// Registration enabled. Tests obtain a fresh fixture, mint an Initial
// Access Token via the public op.Provider API, and POST /oidc/register
// to drive the wire surface end to end.
type dcrFixture struct {
	tk       *testkit.Provider
	endpoint string
}

func newDCRFixture(t *testing.T) *dcrFixture {
	t.Helper()
	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithDynamicRegistration(op.RegistrationOption{}),
	))
	return &dcrFixture{
		tk:       tk,
		endpoint: tk.Server.URL + "/oidc/register",
	}
}

// mintIAT issues a fresh Initial Access Token via the public op API.
func (f *dcrFixture) mintIAT(t *testing.T) string {
	t.Helper()
	issued, err := f.tk.OP.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{})
	if err != nil {
		t.Fatalf("IssueInitialAccessToken: %v", err)
	}
	return issued.Value
}

// post sends a POST /register with the given JSON body and bearer
// (empty bearer omits the Authorization header). contentType="" sends
// the canonical "application/json".
func (f *dcrFixture) post(t *testing.T, bearer, contentType string, body any) *http.Response {
	t.Helper()
	var reader io.Reader = http.NoBody
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, f.endpoint, reader)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if contentType == "" {
		contentType = "application/json"
	}
	req.Header.Set("Content-Type", contentType)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", f.endpoint, err)
	}
	return resp
}

// register is the happy-path POST /register helper used by tests that
// only care about the resulting client and don't need to inspect
// failure paths. It mints a fresh IAT and fails the test if the
// response status is not 201.
func (f *dcrFixture) register(t *testing.T, body map[string]any) (clientID, clientSecret, rat string, decoded map[string]any) {
	t.Helper()
	if body == nil {
		body = map[string]any{
			"redirect_uris": []string{"https://rp.test.invalid/cb"},
		}
	}
	resp := f.post(t, f.mintIAT(t), "", body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /register: status=%d want 201 body=%s", resp.StatusCode, raw)
	}
	got := dcrDecode(t, resp)
	cid, _ := got["client_id"].(string)
	cs, _ := got["client_secret"].(string)
	rt, _ := got["registration_access_token"].(string)
	if cid == "" {
		t.Fatalf("response missing client_id: %+v", got)
	}
	return cid, cs, rt, got
}

// dcrDecode parses a JSON response body as a map.
func dcrDecode(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	return out
}

// TestScenario_DCR_EP_01_CreatedWithMetadataAndNoStore verifies that a
// successful POST /register returns 201 Created with the registered
// metadata as a JSON body and Cache-Control: no-store.
//
// Spec: RFC 7591 §3.2.
func TestScenario_DCR_EP_01_CreatedWithMetadataAndNoStore(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	resp := f.post(t, f.mintIAT(t), "", map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
		"client_name":   "Created Client",
	})
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 201 body=%s", resp.StatusCode, raw)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control=%q want no-store", got)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("Content-Type=%q want application/json", got)
	}
	body := dcrDecode(t, resp)
	if got, _ := body["client_name"].(string); got != "Created Client" {
		t.Errorf("client_name=%q want %q", got, "Created Client")
	}
	if cid, _ := body["client_id"].(string); cid == "" {
		t.Errorf("client_id missing from response: %+v", body)
	}
}

// TestScenario_DCR_EP_02_OnlyJSONContentTypeAccepted confirms that
// only application/json is accepted as the request Content-Type;
// application/x-www-form-urlencoded is rejected with 400 invalid_request.
//
// Spec: RFC 7591 §2.
func TestScenario_DCR_EP_02_OnlyJSONContentTypeAccepted(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	resp := f.post(t, f.mintIAT(t), "application/x-www-form-urlencoded", map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	body := dcrDecode(t, resp)
	if got, _ := body["error"].(string); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request", got)
	}
}

// TestScenario_DCR_EP_03_RedirectURIsMandatory confirms that POST
// /register without redirect_uris is rejected with 400
// invalid_redirect_uri.
//
// Spec: OpenID Connect Dynamic Client Registration 1.0 §2.
func TestScenario_DCR_EP_03_RedirectURIsMandatory(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	resp := f.post(t, f.mintIAT(t), "", map[string]any{
		"client_name": "no-redirects",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	body := dcrDecode(t, resp)
	if got, _ := body["error"].(string); got != "invalid_redirect_uri" {
		t.Errorf("error=%q want invalid_redirect_uri", got)
	}
}

// TestScenario_DCR_EP_04_InvalidEnumRejectedAsClientMetadata verifies
// that an unknown grant_type is rejected with 400 invalid_client_metadata
// and an error_description naming the offending field.
//
// Spec: RFC 7591 §3.2.2.
func TestScenario_DCR_EP_04_InvalidEnumRejectedAsClientMetadata(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	resp := f.post(t, f.mintIAT(t), "", map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
		"grant_types":   []string{"impossible_grant"},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	body := dcrDecode(t, resp)
	if got, _ := body["error"].(string); got != "invalid_client_metadata" {
		t.Errorf("error=%q want invalid_client_metadata", got)
	}
	if desc, _ := body["error_description"].(string); !strings.Contains(desc, "grant_type") {
		t.Errorf("error_description=%q does not name the offending field", desc)
	}
}

func TestScenario_DCR_EP_05_AdapterUpsertCalledOnce(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DCR-EP-05")
}

func TestScenario_DCR_EP_06_RegistrationCreateAuditEmitted(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DCR-EP-06")
}

// TestScenario_DCR_DEF_01_ApplicationTypeDefaultsWeb confirms that the
// OP defaults application_type to "web" when omitted, and the value is
// echoed back in the registration response.
//
// Spec: OpenID Connect Dynamic Client Registration 1.0 §2.
func TestScenario_DCR_DEF_01_ApplicationTypeDefaultsWeb(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	_, _, _, body := f.register(t, map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
	})
	if got, _ := body["application_type"].(string); got != "web" {
		t.Errorf("application_type=%q want web", got)
	}
}

func TestScenario_DCR_DEF_02_IDTokenAlgDefaultsRS256(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DCR-DEF-02 (see catalog out_of_scope_reason)")
}

// TestScenario_DCR_DEF_03_AuthMethodDefaultsBasic confirms that the OP
// defaults token_endpoint_auth_method to "client_secret_basic" when
// the request omits it.
//
// Spec: OpenID Connect Dynamic Client Registration 1.0 §2.
func TestScenario_DCR_DEF_03_AuthMethodDefaultsBasic(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	_, _, _, body := f.register(t, map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
	})
	if got, _ := body["token_endpoint_auth_method"].(string); got != "client_secret_basic" {
		t.Errorf("token_endpoint_auth_method=%q want client_secret_basic", got)
	}
}

func TestScenario_DCR_DEF_04_RequireAuthTimeDefaultsFalse(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DCR-DEF-04")
}

// TestScenario_DCR_DEF_05_GrantTypesDefaultAuthCode confirms that
// grant_types defaults to ["authorization_code"] when omitted. We
// constrain AllowedGrantTypes to a one-element list so the default
// is unambiguous (the library default also admits refresh_token).
//
// Spec: OpenID Connect Dynamic Client Registration 1.0 §2.
func TestScenario_DCR_DEF_05_GrantTypesDefaultAuthCode(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t, testkit.WithOptions(
		op.WithDynamicRegistration(op.RegistrationOption{
			AllowedGrantTypes: []string{"authorization_code"},
		}),
	))
	endpoint := tk.Server.URL + "/oidc/register"
	issued, err := tk.OP.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{})
	if err != nil {
		t.Fatalf("IssueInitialAccessToken: %v", err)
	}
	raw, _ := json.Marshal(map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+issued.Value)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 201 body=%s", resp.StatusCode, body)
	}
	body := dcrDecode(t, resp)
	got, _ := body["grant_types"].([]any)
	if len(got) != 1 {
		t.Fatalf("grant_types=%v want one element", got)
	}
	if s, _ := got[0].(string); s != "authorization_code" {
		t.Errorf("grant_types[0]=%q want authorization_code", s)
	}
}

// TestScenario_DCR_DEF_06_ResponseTypesDefaultCode confirms that
// response_types defaults to ["code"] when omitted.
//
// Spec: OpenID Connect Dynamic Client Registration 1.0 §2.
func TestScenario_DCR_DEF_06_ResponseTypesDefaultCode(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	_, _, _, body := f.register(t, map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
	})
	got, _ := body["response_types"].([]any)
	if len(got) != 1 {
		t.Fatalf("response_types=%v want one element", got)
	}
	if s, _ := got[0].(string); s != "code" {
		t.Errorf("response_types[0]=%q want code", s)
	}
}

// TestScenario_DCR_DEF_07_ClientIDGeneratedUnique confirms that the OP
// mints a fresh client_id for each registration; two consecutive
// registrations under the same configuration MUST yield distinct ids.
//
// Spec: RFC 7591 §3.
func TestScenario_DCR_DEF_07_ClientIDGeneratedUnique(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	cid1, _, _, _ := f.register(t, nil)
	cid2, _, _, _ := f.register(t, nil)
	if cid1 == cid2 {
		t.Errorf("two registrations returned the same client_id %q", cid1)
	}
	if cid1 == "" || cid2 == "" {
		t.Errorf("empty client_id: %q %q", cid1, cid2)
	}
}

// TestScenario_DCR_DEF_08_SecretExpiresAtZeroIsNever confirms that the
// registration response sets client_secret_expires_at: 0 to indicate
// the secret never expires.
//
// Spec: RFC 7591 §3.2.1.
func TestScenario_DCR_DEF_08_SecretExpiresAtZeroIsNever(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	_, _, _, body := f.register(t, map[string]any{
		"redirect_uris":              []string{"https://rp.test.invalid/cb"},
		"token_endpoint_auth_method": "client_secret_basic",
	})
	exp, present := body["client_secret_expires_at"]
	if !present {
		t.Fatalf("client_secret_expires_at missing from response: %+v", body)
	}
	if v, _ := exp.(float64); v != 0 {
		t.Errorf("client_secret_expires_at=%v want 0", exp)
	}
}

func TestScenario_DCR_DEF_09_ClientIDIssuedAtIsEpoch(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DCR-DEF-09")
}

// TestScenario_DCR_SEC_01_NoSecretWhenAuthMethodNone confirms that with
// token_endpoint_auth_method=none the OP does NOT issue a client_secret
// and the field is absent from the response body.
//
// Spec: OpenID Connect Dynamic Client Registration 1.0 §2.
func TestScenario_DCR_SEC_01_NoSecretWhenAuthMethodNone(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	_, secret, _, body := f.register(t, map[string]any{
		"redirect_uris":              []string{"https://rp.test.invalid/cb"},
		"token_endpoint_auth_method": "none",
	})
	if secret != "" {
		t.Errorf("client_secret=%q want empty for public client", secret)
	}
	if _, present := body["client_secret"]; present {
		t.Errorf("client_secret field MUST be omitted when auth_method=none, got body=%+v", body)
	}
}

// TestScenario_DCR_SEC_02_BodySecretIgnoredWhenNotIssued confirms that
// even if the client supplies client_secret / client_secret_expires_at
// in the request body for a public client, the OP ignores them and
// does not persist them.
//
// Spec: RFC 7591 §2.
func TestScenario_DCR_SEC_02_BodySecretIgnoredWhenNotIssued(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	cid, secret, _, body := f.register(t, map[string]any{
		"redirect_uris":              []string{"https://rp.test.invalid/cb"},
		"token_endpoint_auth_method": "none",
		"client_secret":              "smuggled-secret",
		"client_secret_expires_at":   1,
	})
	if secret != "" {
		t.Errorf("client_secret=%q want empty (smuggled value MUST be ignored)", secret)
	}
	if _, present := body["client_secret"]; present {
		t.Errorf("client_secret MUST NOT appear in response: %+v", body)
	}
	persisted, err := f.tk.Store.GetClient(context.Background(), cid)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if persisted.SecretHash != "" {
		t.Errorf("persisted SecretHash=%q want empty for public client", persisted.SecretHash)
	}
}

func TestScenario_DCR_SEC_03_HSIDTokenAlgForcesSecret(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DCR-SEC-03 (see catalog out_of_scope_reason)")
}

func TestScenario_DCR_SEC_04_HSUserInfoOrRequestObjectForcesSecret(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DCR-SEC-04 (see catalog out_of_scope_reason)")
}

// TestScenario_DCR_SEC_05_SecretBasedAuthMethodIssuesSecret confirms
// that for token_endpoint_auth_method values that consume a server-
// issued secret (client_secret_basic, client_secret_post) the OP mints
// a client_secret and includes it in the response. (v1.0 does not
// implement client_secret_jwt; see DCR-SEC-05 catalog text.)
//
// Spec: OpenID Connect Dynamic Client Registration 1.0 §2.
func TestScenario_DCR_SEC_05_SecretBasedAuthMethodIssuesSecret(t *testing.T) {
	t.Parallel()

	for _, method := range []string{"client_secret_basic", "client_secret_post"} {
		method := method
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			f := newDCRFixture(t)
			_, secret, _, body := f.register(t, map[string]any{
				"redirect_uris":              []string{"https://rp.test.invalid/cb"},
				"token_endpoint_auth_method": method,
			})
			if secret == "" {
				t.Errorf("client_secret missing from response for %s: %+v", method, body)
			}
		})
	}
}

// TestScenario_DCR_SEC_06_SecretEntropyAtLeast256Bits confirms that the
// generated client_secret carries at least 256 bits of entropy. v1.0
// emits the secret as base64url-encoded random bytes; 256 bits = 32
// bytes, which encodes to ≥ 43 base64url characters.
//
// Spec: NIST SP 800-63B / OWASP.
func TestScenario_DCR_SEC_06_SecretEntropyAtLeast256Bits(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	_, secret, _, _ := f.register(t, map[string]any{
		"redirect_uris":              []string{"https://rp.test.invalid/cb"},
		"token_endpoint_auth_method": "client_secret_basic",
	})
	if secret == "" {
		t.Fatal("client_secret missing")
	}
	// base64url decode (no padding) and assert the underlying bytes
	// are at least 32 (256 bits). The library uses
	// base64.RawURLEncoding for client_secret so a strict decode is
	// the correct shape check.
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil {
		t.Fatalf("client_secret %q is not base64url-no-padding: %v", secret, err)
	}
	if len(decoded) < 32 {
		t.Errorf("client_secret entropy = %d bytes; want ≥ 32 (256 bits)", len(decoded))
	}
}

func TestScenario_DCR_SEC_07_SecretMaskedInLogs(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DCR-SEC-07")
}

func TestScenario_DCR_IAT_01_FixedStringIATRequiresBearer(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DCR-IAT-01 (see catalog out_of_scope_reason)")
}

func TestScenario_DCR_IAT_02_AdapterIATEntityRequired(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DCR-IAT-02 (see catalog out_of_scope_reason)")
}

func TestScenario_DCR_IAT_03_IATCreationAPIAvailable(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DCR-IAT-03")
}

// TestScenario_DCR_IAT_04_MissingOrInvalidIATIs401 confirms that POST
// /register without an Authorization header yields 401 invalid_token.
// Presenting an unknown bearer also yields 401 invalid_token.
//
// Spec: RFC 6750 §3.1 / RFC 7591 §3.
func TestScenario_DCR_IAT_04_MissingOrInvalidIATIs401(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	missing := f.post(t, "", "", map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
	})
	defer func() { _ = missing.Body.Close() }()
	if missing.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(missing.Body)
		t.Fatalf("missing IAT status=%d want 401 body=%s", missing.StatusCode, raw)
	}
	body := dcrDecode(t, missing)
	if got, _ := body["error"].(string); got != "invalid_token" {
		t.Errorf("error=%q want invalid_token", got)
	}

	// Unknown / never-issued bearer.
	bad := f.post(t, "an-iat-the-op-never-issued", "", map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
	})
	defer func() { _ = bad.Body.Close() }()
	if bad.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(bad.Body)
		t.Fatalf("unknown IAT status=%d want 401 body=%s", bad.StatusCode, raw)
	}
	body2 := dcrDecode(t, bad)
	if got, _ := body2["error"].(string); got != "invalid_token" {
		t.Errorf("unknown IAT error=%q want invalid_token", got)
	}
}

func TestScenario_DCR_IAT_05_IATEntityAttachedToContext(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DCR-IAT-05")
}

func TestScenario_DCR_IAT_06_PublicDCRSupportedButDiscouraged(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DCR-IAT-06")
}

// TestScenario_DCR_IAT_07_ManipulatedIATRejected confirms that a
// truncated / mutated IAT value yields 401 invalid_token.
//
// Spec: RFC 6750 §3.1.
func TestScenario_DCR_IAT_07_ManipulatedIATRejected(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	iat := f.mintIAT(t)
	if len(iat) < 4 {
		t.Fatalf("IAT %q too short to mutate", iat)
	}
	mangled := iat[:len(iat)-2] + "AA" // change the last two characters
	if mangled == iat {
		mangled = iat[:len(iat)-2] + "BB"
	}
	resp := f.post(t, mangled, "", map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	body := dcrDecode(t, resp)
	if got, _ := body["error"].(string); got != "invalid_token" {
		t.Errorf("error=%q want invalid_token", got)
	}
}

// TestScenario_DCR_RAT_01_RATIssuedByDefault confirms that POST
// /register issues a Registration Access Token and surfaces it
// alongside registration_client_uri in the response body.
//
// Spec: RFC 7592 §3.
func TestScenario_DCR_RAT_01_RATIssuedByDefault(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	cid, _, rat, body := f.register(t, nil)
	if rat == "" {
		t.Errorf("registration_access_token missing: %+v", body)
	}
	uri, _ := body["registration_client_uri"].(string)
	if uri == "" {
		t.Errorf("registration_client_uri missing: %+v", body)
	}
	if !strings.HasSuffix(uri, "/oidc/register/"+cid) {
		t.Errorf("registration_client_uri=%q must end with /oidc/register/%s", uri, cid)
	}
}

func TestScenario_DCR_RAT_02_RATIssuanceCanBeSuppressed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DCR-RAT-02")
}

func TestScenario_DCR_RAT_03_RATIssuanceFunctionTrue(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DCR-RAT-03")
}

// TestScenario_DCR_RAT_04_RATBoundToIssuingClient confirms that an RAT
// minted for client A cannot be replayed against client B's
// /register/{client_id}; the OP responds 401 invalid_token. (The
// registration_management catalog covers the management-side semantics
// in detail; this is the smoke test from the dynamic_registration
// surface.)
//
// Spec: RFC 7592 §2.
func TestScenario_DCR_RAT_04_RATBoundToIssuingClient(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	_, _, ratA, _ := f.register(t, nil)
	cidB, _, _, _ := f.register(t, nil)

	// Replay client A's RAT against client B's record.
	target := f.endpoint + "/" + cidB
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+ratA)
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	body := dcrDecode(t, resp)
	if got, _ := body["error"].(string); got != "invalid_token" {
		t.Errorf("error=%q want invalid_token", got)
	}
}

func TestScenario_DCR_CTX_01_EntitiesContainClientAndRAT(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DCR-CTX-01")
}

func TestScenario_DCR_CTX_02_EntitiesIncludeIATWhenInUse(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DCR-CTX-02")
}

func TestScenario_DCR_CTX_03_EntitiesOmitRATWhenSuppressed(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DCR-CTX-03")
}

// TestScenario_DCR_STATIC_01_AdapterFindReturnsBothKinds confirms that
// the public store API resolves both static (op.WithStaticClients-
// seeded) and DCR-issued clients via the same GetClient call. The
// only structural difference is the Source field
// (ClientSourceStatic vs ClientSourceDynamic).
//
// Spec: OP design.
func TestScenario_DCR_STATIC_01_AdapterFindReturnsBothKinds(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	staticClient := f.tk.RegisterClient(t, testkit.ClientFixture{
		ID:           "static-rp",
		PublicClient: true,
		RedirectURIs: []string{"https://rp.test.invalid/cb"},
	})
	dynamicID, _, _, _ := f.register(t, nil)

	gotStatic, err := f.tk.Store.GetClient(context.Background(), staticClient.ID)
	if err != nil {
		t.Fatalf("GetClient(static): %v", err)
	}
	gotDynamic, err := f.tk.Store.GetClient(context.Background(), dynamicID)
	if err != nil {
		t.Fatalf("GetClient(dynamic): %v", err)
	}
	if gotStatic.Source == store.ClientSourceDynamic {
		t.Errorf("static client Source=%v want non-dynamic", gotStatic.Source)
	}
	if gotDynamic.Source != store.ClientSourceDynamic {
		t.Errorf("dynamic client Source=%v want %v", gotDynamic.Source, store.ClientSourceDynamic)
	}
	if gotStatic.ID == gotDynamic.ID {
		t.Errorf("static and dynamic clients share id %q", gotStatic.ID)
	}
}

// TestScenario_DCR_STATIC_02_StaticClientsHaveNoRAT confirms that
// static (op.WithStaticClients-seeded / RegisterClient-seeded) clients
// never receive a Registration Access Token, so RFC 7592 management
// operations against them are rejected. The OP returns 401
// invalid_token rather than 403 to defeat enumeration (a 403 would
// distinguish "static client exists" from "RAT mismatch"); the
// substantive contract — "no RAT, no manageability" — is the same.
//
// Spec: RFC 7592 §2.
func TestScenario_DCR_STATIC_02_StaticClientsHaveNoRAT(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	staticClient := f.tk.RegisterClient(t, testkit.ClientFixture{
		ID:           "static-no-rat",
		PublicClient: true,
		RedirectURIs: []string{"https://rp.test.invalid/cb"},
	})

	// Even with a syntactically valid bearer (we use a freshly minted
	// IAT to avoid dependence on RAT shape), the management endpoint
	// rejects the static client because no RAT row exists for it and
	// the client's Source != ClientSourceDynamic.
	bearer := f.mintIAT(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.endpoint+"/"+staticClient.ID, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	body := dcrDecode(t, resp)
	if got, _ := body["error"].(string); got != "invalid_token" {
		t.Errorf("error=%q want invalid_token", got)
	}

	// Confirm the public store API agrees: no RAT row for the static
	// client.
	if _, err := f.tk.Store.RegistrationAccessTokens().GetByClientID(context.Background(), staticClient.ID); err == nil {
		t.Errorf("RegistrationAccessTokens.GetByClientID(%q) unexpectedly succeeded for static client", staticClient.ID)
	}
}

// TestScenario_DCR_GET_01_GetRequiresBearerRAT confirms that the
// management endpoint requires the RAT to flow through the
// Authorization: Bearer header. Passing access_token in the query
// string yields 401 invalid_token (no Bearer credential present).
//
// Spec: RFC 7592 §2.1.
func TestScenario_DCR_GET_01_GetRequiresBearerRAT(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	cid, _, rat, _ := f.register(t, nil)
	target := f.endpoint + "/" + cid + "?access_token=" + rat

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	body := dcrDecode(t, resp)
	if got, _ := body["error"].(string); got != "invalid_token" {
		t.Errorf("error=%q want invalid_token", got)
	}
}

// TestScenario_DCR_GET_02_GetReturnsNonSecretMetadata confirms the GET
// /register/{client_id} response carries every non-secret metadata
// field. client_secret is included only when the registered
// authentication method consumes it. Read-back of a confidential
// client must echo the client_id; read-back of a public client (auth
// method "none") MUST omit client_secret.
//
// Spec: RFC 7592 §2.1.
func TestScenario_DCR_GET_02_GetReturnsNonSecretMetadata(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	// Public client: client_secret is never minted, so it must be
	// absent from the GET response.
	cid, _, rat, _ := f.register(t, map[string]any{
		"redirect_uris":              []string{"https://rp.test.invalid/cb"},
		"token_endpoint_auth_method": "none",
		"client_name":                "Public Client",
	})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.endpoint+"/"+cid, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+rat)
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body := dcrDecode(t, resp)
	if got, _ := body["client_id"].(string); got != cid {
		t.Errorf("client_id=%q want %q", got, cid)
	}
	if got, _ := body["client_name"].(string); got != "Public Client" {
		t.Errorf("client_name=%q want %q", got, "Public Client")
	}
	if _, present := body["client_secret"]; present {
		t.Errorf("client_secret MUST be absent for auth_method=none, got body=%+v", body)
	}
}

func TestScenario_DCR_GET_03_GetSetsNoStore(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DCR-GET-03")
}

func TestScenario_DCR_GET_04_CrossClientRATAutoDestroyed(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DCR-GET-04 (see catalog out_of_scope_reason)")
}

// TestScenario_DCR_GET_05_ManipulatedRATRejected confirms that GET
// /register/{client_id} with a truncated or otherwise mutated RAT
// yields 401 invalid_token.
//
// Spec: RFC 6750 §3.1.
func TestScenario_DCR_GET_05_ManipulatedRATRejected(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	cid, _, rat, _ := f.register(t, nil)
	if len(rat) < 4 {
		t.Fatalf("RAT %q too short", rat)
	}
	mangled := rat[:len(rat)-2] + "ZZ"
	if mangled == rat {
		mangled = rat[:len(rat)-2] + "YY"
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, f.endpoint+"/"+cid, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+mangled)
	resp, err := f.tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	body := dcrDecode(t, resp)
	if got, _ := body["error"].(string); got != "invalid_token" {
		t.Errorf("error=%q want invalid_token", got)
	}
}

func TestScenario_DCR_GET_06_StaticClientReadForbidden(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DCR-GET-06 (see catalog out_of_scope_reason)")
}

// TestScenario_DCR_VAL_01_RedirectURIsArrayMinOne confirms that a
// redirect_uri carrying a fragment is rejected with 400
// invalid_redirect_uri (the array+min-one rule is exercised by
// DCR-EP-03; the fragment rule is the per-entry shape check).
//
// Spec: RFC 6749 §3.1.2 / OIDC Dynamic Client Registration 1.0 §2.
func TestScenario_DCR_VAL_01_RedirectURIsArrayMinOne(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	resp := f.post(t, f.mintIAT(t), "", map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb#frag"},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	body := dcrDecode(t, resp)
	if got, _ := body["error"].(string); got != "invalid_redirect_uri" {
		t.Errorf("error=%q want invalid_redirect_uri", got)
	}
}

// TestScenario_DCR_VAL_02_ApplicationTypeURIScheme confirms the
// scheme-policy split: web clients require https; non-https web
// redirect_uris are rejected with 400 invalid_redirect_uri.
//
// Spec: OpenID Connect Core 1.0 §2.
func TestScenario_DCR_VAL_02_ApplicationTypeURIScheme(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	// http://app.example/cb is neither https nor a loopback IP, so the
	// web-client policy rejects it.
	resp := f.post(t, f.mintIAT(t), "", map[string]any{
		"redirect_uris":    []string{"http://app.example/cb"},
		"application_type": "web",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	body := dcrDecode(t, resp)
	if got, _ := body["error"].(string); got != "invalid_redirect_uri" {
		t.Errorf("error=%q want invalid_redirect_uri", got)
	}
}

// TestScenario_DCR_VAL_03_GrantTypesMustBeSupported confirms that a
// grant_type outside the OP's AllowedGrantTypes set is rejected with
// 400 invalid_client_metadata.
//
// Spec: RFC 7591 §2 / RFC 7592 §2.
func TestScenario_DCR_VAL_03_GrantTypesMustBeSupported(t *testing.T) {
	t.Parallel()

	// Default AllowedGrantTypes = {authorization_code, refresh_token};
	// urn:ietf:params:oauth:grant-type:jwt-bearer is outside.
	f := newDCRFixture(t)
	resp := f.post(t, f.mintIAT(t), "", map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
		"grant_types":   []string{"urn:ietf:params:oauth:grant-type:jwt-bearer"},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	body := dcrDecode(t, resp)
	if got, _ := body["error"].(string); got != "invalid_client_metadata" {
		t.Errorf("error=%q want invalid_client_metadata", got)
	}
}

func TestScenario_DCR_VAL_04_ResponseTypesAlignedWithGrants(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DCR-VAL-04 (see catalog out_of_scope_reason)")
}

// TestScenario_DCR_VAL_05_JWKSAndJWKSURIExclusive confirms that
// supplying both jwks and jwks_uri is rejected with 400
// invalid_client_metadata.
//
// Spec: OpenID Connect Core 1.0 §16.5.
func TestScenario_DCR_VAL_05_JWKSAndJWKSURIExclusive(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	resp := f.post(t, f.mintIAT(t), "", map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
		"jwks_uri":      "https://rp.test.invalid/jwks.json",
		"jwks": map[string]any{
			"keys": []any{},
		},
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	body := dcrDecode(t, resp)
	if got, _ := body["error"].(string); got != "invalid_client_metadata" {
		t.Errorf("error=%q want invalid_client_metadata", got)
	}
}

// TestScenario_DCR_VAL_06_SectorIdentifierURIRules confirms that a
// sector_identifier_uri using a non-https scheme is rejected with 400
// invalid_client_metadata. (The full §8.1 fetch-and-contain rule is
// covered by integration tests in registrationendpoint; this scenario
// pins the wire-level scheme check that runs before any outbound
// fetch.)
//
// Spec: OpenID Connect Core 1.0 §8.1.
func TestScenario_DCR_VAL_06_SectorIdentifierURIRules(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	resp := f.post(t, f.mintIAT(t), "", map[string]any{
		"redirect_uris":         []string{"https://rp.test.invalid/cb"},
		"sector_identifier_uri": "http://rp.test.invalid/sector.json",
	})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	body := dcrDecode(t, resp)
	if got, _ := body["error"].(string); got != "invalid_client_metadata" {
		t.Errorf("error=%q want invalid_client_metadata", got)
	}
}

func TestScenario_DCR_VAL_07_PairwiseHostHomogeneityWithoutSector(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DCR-VAL-07 (see catalog out_of_scope_reason)")
}

func TestScenario_DCR_VAL_08_TLSClientAuthFieldExclusivity(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DCR-VAL-08 (see catalog out_of_scope_reason)")
}

func TestScenario_DCR_VAL_09_EncryptionAlgsBoundedByEnabledJWA(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: DCR-VAL-09 (see catalog out_of_scope_reason)")
}

func TestScenario_DCR_VAL_10_DefaultMaxAgeNonNegative(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DCR-VAL-10")
}

func TestScenario_DCR_VAL_11_RequestObjectAlgNoneRejected(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DCR-VAL-11")
}

// TestScenario_DCR_ERR_01_ErrorCodesLimitedSet exercises the four
// admitted RFC 7591 §3.2.2 wire codes and confirms that no other
// error code can leak from the registration endpoint:
//   - invalid_redirect_uri (missing redirect_uris)
//   - invalid_client_metadata (unknown grant_type)
//   - invalid_request (wrong content-type)
//   - invalid_token (missing IAT)
//
// Spec: RFC 7591 §3.2.2.
func TestScenario_DCR_ERR_01_ErrorCodesLimitedSet(t *testing.T) {
	t.Parallel()

	f := newDCRFixture(t)
	allowed := map[string]struct{}{
		"invalid_redirect_uri":    {},
		"invalid_client_metadata": {},
		"invalid_request":         {},
		"invalid_token":           {},
	}

	cases := []struct {
		name        string
		bearer      string
		contentType string
		body        any
		wantCode    string
	}{
		{
			name:     "missing redirect_uris -> invalid_redirect_uri",
			bearer:   f.mintIAT(t),
			body:     map[string]any{"client_name": "no-redirect"},
			wantCode: "invalid_redirect_uri",
		},
		{
			name:   "unknown grant_type -> invalid_client_metadata",
			bearer: f.mintIAT(t),
			body: map[string]any{
				"redirect_uris": []string{"https://rp.test.invalid/cb"},
				"grant_types":   []string{"impossible"},
			},
			wantCode: "invalid_client_metadata",
		},
		{
			name:        "wrong content-type -> invalid_request",
			bearer:      f.mintIAT(t),
			contentType: "application/x-www-form-urlencoded",
			body: map[string]any{
				"redirect_uris": []string{"https://rp.test.invalid/cb"},
			},
			wantCode: "invalid_request",
		},
		{
			name:     "missing bearer -> invalid_token",
			bearer:   "",
			body:     map[string]any{"redirect_uris": []string{"https://rp.test.invalid/cb"}},
			wantCode: "invalid_token",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := f.post(t, tc.bearer, tc.contentType, tc.body)
			defer func() { _ = resp.Body.Close() }()
			body := dcrDecode(t, resp)
			got, _ := body["error"].(string)
			if got != tc.wantCode {
				t.Errorf("error=%q want %q", got, tc.wantCode)
			}
			if _, ok := allowed[got]; !ok {
				t.Errorf("error=%q not in the §3.2.2 admitted set", got)
			}
		})
	}
}

func TestScenario_DCR_ERR_02_NoWWWAuthenticateOnNonBearer(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DCR-ERR-02")
}

func TestScenario_DCR_ERR_03_NoInternalDetailLeak(t *testing.T) {
	t.Parallel()
	t.Skip("pending: DCR-ERR-03")
}
