package registrationendpoint_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// dcrCreated bundles the result of a successful POST /register so
// management tests can drive GET / PUT / DELETE without re-registering
// every time.
type dcrCreated struct {
	clientID                string
	clientIDIssuedAt        int64
	registrationAccessToken string
	registrationClientURI   string
}

// register issues a POST /register and returns the parsed response.
// Tests that need to drive the management endpoints typically call
// this helper once and then operate on dcrCreated.
//
// The registration_client_uri returned by the OP is rooted at the
// configured Issuer (https://op.testkit.invalid in the testkit), which
// the test client cannot reach over the network. We rewrite it to the
// httptest server URL so the tests exercise the same routing the OP
// would serve in production.
func (f *dcrFixture) register(tb testing.TB, body any) dcrCreated {
	tb.Helper()
	_, iat := f.issueIAT(tb, op.InitialAccessTokenSpec{})
	if body == nil {
		body = minimalMetadata()
	}
	resp := f.post(tb, body, iat)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		tb.Fatalf("register: status=%d want 201 body=%s", resp.StatusCode, raw)
	}
	got := decodeBody(tb, resp)
	out := dcrCreated{}
	out.clientID, _ = got["client_id"].(string)
	if issued, ok := got["client_id_issued_at"].(float64); ok {
		out.clientIDIssuedAt = int64(issued)
	}
	out.registrationAccessToken, _ = got["registration_access_token"].(string)
	advertised, _ := got["registration_client_uri"].(string)
	if out.clientID == "" || out.registrationAccessToken == "" || advertised == "" {
		tb.Fatalf("register: malformed response %+v", got)
	}
	out.registrationClientURI = f.endpoint + "/" + out.clientID
	return out
}

// manage issues a request against /register/{client_id} with the
// supplied method, optional JSON body, and Bearer credential.
func (f *dcrFixture) manage(tb testing.TB, method, path, bearer string, body any) *http.Response {
	tb.Helper()
	var reader io.Reader
	switch v := body.(type) {
	case nil:
		reader = http.NoBody
	case string:
		reader = strings.NewReader(v)
	default:
		raw, err := json.Marshal(body)
		if err != nil {
			tb.Fatalf("marshal: %v", err)
		}
		reader = strings.NewReader(string(raw))
	}
	req, err := http.NewRequestWithContext(context.Background(), method, path, reader)
	if err != nil {
		tb.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := f.prov.HTTPClient(nil).Do(req)
	if err != nil {
		tb.Fatalf("Do: %v", err)
	}
	return resp
}

// TestManage_Read_HappyPath confirms GET /register/{client_id} returns
// 200 + canonical metadata under the active RAT.
func TestManage_Read_HappyPath(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	created := f.register(t, nil)

	resp := f.manage(t, http.MethodGet, created.registrationClientURI, created.registrationAccessToken, nil)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body := decodeBody(t, resp)
	if got, _ := body["client_id"].(string); got != created.clientID {
		t.Errorf("client_id=%v want %q", body["client_id"], created.clientID)
	}
	if got, _ := body["client_id_issued_at"].(float64); int64(got) != created.clientIDIssuedAt {
		t.Errorf("client_id_issued_at=%v want %d", body["client_id_issued_at"], created.clientIDIssuedAt)
	}
	// Per RFC 7592 §2.1 the GET response MUST NOT echo a fresh RAT.
	if rat, ok := body["registration_access_token"].(string); ok && rat != "" {
		t.Errorf("GET response must not include a registration_access_token, got %q", rat)
	}
	assertCacheControl(t, resp)
}

// TestManage_Read_4xx covers the RAT verification error matrix.
func TestManage_Read_4xx(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		buildRequest func(t *testing.T, f *dcrFixture, c dcrCreated) (path, bearer string)
	}{
		{
			name: "no RAT",
			buildRequest: func(_ *testing.T, _ *dcrFixture, c dcrCreated) (string, string) {
				return c.registrationClientURI, ""
			},
		},
		{
			name: "wrong RAT",
			buildRequest: func(_ *testing.T, _ *dcrFixture, c dcrCreated) (string, string) {
				return c.registrationClientURI, "bogus-rat-not-on-file"
			},
		},
		{
			name: "RAT for a different client",
			buildRequest: func(t *testing.T, f *dcrFixture, _ dcrCreated) (string, string) {
				t.Helper()
				other := f.register(t, nil)
				// Prepare the URL targeting a *different* client_id than
				// the RAT was minted for. We swap the trailing segment of
				// the second client's registration_client_uri for the
				// first client's id.
				first := f.register(t, nil)
				path := other.registrationClientURI[:strings.LastIndex(other.registrationClientURI, "/")] + "/" + first.clientID
				return path, other.registrationAccessToken
			},
		},
		{
			name: "unknown client_id",
			buildRequest: func(_ *testing.T, _ *dcrFixture, c dcrCreated) (string, string) {
				path := c.registrationClientURI[:strings.LastIndex(c.registrationClientURI, "/")] + "/no-such-client"
				return path, c.registrationAccessToken
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, op.RegistrationOption{})
			c := f.register(t, nil)
			path, bearer := tc.buildRequest(t, f, c)
			resp := f.manage(t, http.MethodGet, path, bearer, nil)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				raw, _ := io.ReadAll(resp.Body)
				t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
			}
			got := decodeBody(t, resp)
			if got["error"] != "invalid_token" {
				t.Errorf("error=%v want invalid_token", got["error"])
			}
		})
	}
}

// TestManage_Read_StaticClientWithFakeRAT confirms enumeration defence:
// the handler must reject a RAT presented against a Source=static client
// with the same invalid_token envelope it returns for an unknown client.
func TestManage_Read_StaticClientWithFakeRAT(t *testing.T) {
	t.Parallel()

	const staticID = "static-via-config"
	f := dcrFixtureWithStaticClient(t, staticID)
	// Even if we somehow obtained a syntactically valid RAT (we use a
	// random string here), the handler must reject the management call
	// because Source != Dynamic.
	path := f.endpoint + "/" + staticID
	resp := f.manage(t, http.MethodGet, path, "any-rat-value", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 401 body=%s", resp.StatusCode, raw)
	}
	got := decodeBody(t, resp)
	if got["error"] != "invalid_token" {
		t.Errorf("error=%v want invalid_token", got["error"])
	}
}

// TestManage_Update_HappyPath_RotatesRAT confirms PUT issues a fresh
// RAT, the old RAT becomes invalid, and the metadata is persisted.
func TestManage_Update_HappyPath_RotatesRAT(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	created := f.register(t, nil)
	updated := minimalMetadata()
	updated["redirect_uris"] = []string{"https://rp.test.invalid/cb-new"}
	updated["client_name"] = "Renamed Client"

	resp := f.manage(t, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, updated)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body := decodeBody(t, resp)
	newRAT, _ := body["registration_access_token"].(string)
	if newRAT == "" {
		t.Fatal("PUT response must include a fresh registration_access_token")
	}
	if newRAT == created.registrationAccessToken {
		t.Error("PUT must rotate the RAT, got the same value")
	}
	uris, _ := body["redirect_uris"].([]any)
	if len(uris) != 1 || uris[0] != "https://rp.test.invalid/cb-new" {
		t.Errorf("redirect_uris=%v want [cb-new]", uris)
	}
	if got, _ := body["client_name"].(string); got != "Renamed Client" {
		t.Errorf("client_name=%q want \"Renamed Client\" (PUT must round-trip the OIDC profile)", got)
	}

	// The previous RAT must no longer authenticate.
	stale := f.manage(t, http.MethodGet, created.registrationClientURI, created.registrationAccessToken, nil)
	defer stale.Body.Close()
	if stale.StatusCode != http.StatusUnauthorized {
		t.Errorf("stale RAT GET status=%d want 401", stale.StatusCode)
	}

	// The new RAT MUST authenticate.
	fresh := f.manage(t, http.MethodGet, created.registrationClientURI, newRAT, nil)
	defer fresh.Body.Close()
	if fresh.StatusCode != http.StatusOK {
		t.Errorf("fresh RAT GET status=%d want 200", fresh.StatusCode)
	}
}

func TestManage_Update_IgnoresStandardUnstoredMetadata(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	created := f.register(t, nil)
	updated := minimalMetadata()
	updated["client_name"] = "Client With Ignored Metadata"
	updated["software_id"] = "software-456"
	updated["software_version"] = "2026.7"
	updated["tls_client_certificate_bound_access_tokens"] = true
	updated["backchannel_token_delivery_mode"] = "ping"
	updated["backchannel_client_notification_endpoint"] = "https://rp.test.invalid/ciba/ping"
	updated["backchannel_authentication_request_signing_alg"] = "ES256"
	updated["backchannel_user_code_parameter"] = false
	updated["authorization_signed_response_alg"] = "ES256"
	updated["authorization_details_types"] = []string{"payment_initiation"}

	resp := f.manage(t, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, updated)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	got := decodeBody(t, resp)
	if got["client_name"] != "Client With Ignored Metadata" {
		t.Fatalf("client_name=%v want update to persist", got["client_name"])
	}
	for _, ignored := range []string{
		"software_id",
		"software_version",
		"tls_client_certificate_bound_access_tokens",
		"backchannel_token_delivery_mode",
		"backchannel_client_notification_endpoint",
		"backchannel_authentication_request_signing_alg",
		"backchannel_user_code_parameter",
		"authorization_signed_response_alg",
		"authorization_details_types",
	} {
		if _, ok := got[ignored]; ok {
			t.Errorf("response echoed ignored metadata %q: %v", ignored, got[ignored])
		}
	}
}

func TestManage_Update_PublicToConfidential_MintsClientSecret(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	created := f.register(t, map[string]any{
		"redirect_uris":              []string{"https://rp.test.invalid/cb"},
		"token_endpoint_auth_method": "none",
	})

	update := map[string]any{
		"redirect_uris":              []string{"https://rp.test.invalid/cb"},
		"token_endpoint_auth_method": "client_secret_basic",
	}
	resp := f.manage(t, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, update)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body := decodeBody(t, resp)
	secret, _ := body["client_secret"].(string)
	if secret == "" {
		t.Fatal("PUT response must include a newly minted client_secret")
	}
	if got, _ := body["client_id_issued_at"].(float64); int64(got) != created.clientIDIssuedAt {
		t.Fatalf("client_id_issued_at=%v want %d", body["client_id_issued_at"], created.clientIDIssuedAt)
	}
	client, err := f.prov.Store.GetClient(context.Background(), created.clientID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if client.PublicClient {
		t.Fatal("updated client must be confidential")
	}
	if client.SecretHash == "" {
		t.Fatal("updated client must persist a secret hash")
	}
	if client.ClientIDIssuedAt != created.clientIDIssuedAt {
		t.Fatalf("persisted client_id_issued_at=%d want %d", client.ClientIDIssuedAt, created.clientIDIssuedAt)
	}
}

func TestManage_Update_AllowsOptionalPropertiesToBeDeleted(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	created := f.register(t, map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
		"client_name":   "example client",
	})

	resp := f.manage(t, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
		"client_name":   nil,
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body := decodeBody(t, resp)
	if _, ok := body["client_name"]; ok {
		t.Fatalf("client_name should be deleted, got %v", body["client_name"])
	}
	client, err := f.prov.Store.GetClient(context.Background(), created.clientID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if client.ClientName != "" {
		t.Fatalf("persisted client_name=%q want empty", client.ClientName)
	}
}

func TestManage_Update_AllowsOptionalPropertiesToBeDeletedByOmission(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	created := f.register(t, map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
		"client_name":   "example client",
	})

	resp := f.manage(t, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
	})
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}
	body := decodeBody(t, resp)
	if _, ok := body["client_name"]; ok {
		t.Fatalf("client_name should be deleted by omission, got %v", body["client_name"])
	}
	client, err := f.prov.Store.GetClient(context.Background(), created.clientID)
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if client.ClientName != "" {
		t.Fatalf("persisted client_name=%q want empty", client.ClientName)
	}
}

// TestManage_Update_RejectsClientIDOverride confirms attempting to
// change client_id via the body is a 400 invalid_request.
func TestManage_Update_RejectsClientIDOverride(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	created := f.register(t, nil)
	body := minimalMetadata()
	body["client_id"] = "trying-to-rename"
	resp := f.manage(t, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
	}
	got := decodeBody(t, resp)
	if got["error"] != "invalid_request" {
		t.Errorf("error=%v want invalid_request", got["error"])
	}
}

func TestManage_Update_RejectsReservedFieldsAndMismatchedClientSecret(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		initial     map[string]any
		mutate      func(map[string]any)
		wantMessage string
	}{
		{
			name: "registration_access_token",
			mutate: func(b map[string]any) {
				b["registration_access_token"] = "rat"
			},
			wantMessage: "request MUST NOT include the registration_access_token field",
		},
		{
			name: "registration_client_uri",
			mutate: func(b map[string]any) {
				b["registration_client_uri"] = "https://op.example/register/client"
			},
			wantMessage: "request MUST NOT include the registration_client_uri field",
		},
		{
			name: "client_secret_expires_at",
			mutate: func(b map[string]any) {
				b["client_secret_expires_at"] = 0
			},
			wantMessage: "request MUST NOT include the client_secret_expires_at field",
		},
		{
			name: "client_id_issued_at",
			mutate: func(b map[string]any) {
				b["client_id_issued_at"] = 123
			},
			wantMessage: "request MUST NOT include the client_id_issued_at field",
		},
		{
			name: "mismatched client_secret",
			initial: map[string]any{
				"redirect_uris":              []string{"https://rp.test.invalid/cb"},
				"token_endpoint_auth_method": "client_secret_basic",
			},
			mutate: func(b map[string]any) {
				b["client_secret"] = "wrong-secret"
			},
			wantMessage: "provided client_secret does not match the authenticated client's one",
		},
		{
			name: "null client_secret",
			initial: map[string]any{
				"redirect_uris":              []string{"https://rp.test.invalid/cb"},
				"token_endpoint_auth_method": "client_secret_basic",
			},
			mutate: func(b map[string]any) {
				b["client_secret"] = nil
			},
			wantMessage: "provided client_secret does not match the authenticated client's one",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, op.RegistrationOption{})
			initial := tc.initial
			if initial == nil {
				initial = minimalMetadata()
			}
			created := f.register(t, initial)
			body := minimalMetadata()
			if tc.initial != nil {
				body["token_endpoint_auth_method"] = tc.initial["token_endpoint_auth_method"]
			}
			tc.mutate(body)
			resp := f.manage(t, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, body)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				raw, _ := io.ReadAll(resp.Body)
				t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
			}
			got := decodeBody(t, resp)
			if got["error"] != "invalid_request" {
				t.Fatalf("error=%v want invalid_request", got["error"])
			}
			if got["error_description"] != tc.wantMessage {
				t.Fatalf("error_description=%v want %q", got["error_description"], tc.wantMessage)
			}
		})
	}
}

// TestManage_Update_MetadataValidationErrors mirrors the POST validation
// matrix for PUT.
func TestManage_Update_MetadataValidationErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		mutate    func(map[string]any)
		wantError string
	}{
		{
			name: "missing redirect_uris",
			mutate: func(b map[string]any) {
				delete(b, "redirect_uris")
			},
			wantError: "invalid_redirect_uri",
		},
		{
			name: "disallowed grant_type",
			mutate: func(b map[string]any) {
				b["grant_types"] = []string{"client_credentials"}
			},
			wantError: "invalid_client_metadata",
		},
		{
			name: "client_secret_jwt rejected",
			mutate: func(b map[string]any) {
				b["token_endpoint_auth_method"] = "client_secret_jwt"
			},
			wantError: "invalid_client_metadata",
		},
		{
			name: "software_statement rejected",
			mutate: func(b map[string]any) {
				b["software_statement"] = "ey.fake.jwt"
			},
			wantError: "invalid_software_statement",
		},
		{
			name: "jwks and jwks_uri mutually exclusive",
			mutate: func(b map[string]any) {
				b["jwks"] = map[string]any{"keys": []any{}}
				b["jwks_uri"] = "https://rp.test.invalid/jwks.json"
			},
			wantError: "invalid_client_metadata",
		},
		{
			name: "code response_type requires authorization_code grant",
			mutate: func(b map[string]any) {
				b["grant_types"] = []string{"implicit"}
				b["response_types"] = []string{"code"}
			},
			wantError: "invalid_client_metadata",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, op.RegistrationOption{})
			created := f.register(t, nil)
			body := minimalMetadata()
			tc.mutate(body)
			resp := f.manage(t, http.MethodPut, created.registrationClientURI, created.registrationAccessToken, body)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusBadRequest {
				raw, _ := io.ReadAll(resp.Body)
				t.Fatalf("status=%d want 400 body=%s", resp.StatusCode, raw)
			}
			got := decodeBody(t, resp)
			if got["error"] != tc.wantError {
				t.Errorf("error=%v want %q", got["error"], tc.wantError)
			}
		})
	}
}

// TestManage_Delete_HappyPath confirms DELETE returns 204 and that
// every subsequent GET / PUT / DELETE returns 401 (enumeration defence
// — we cannot tell "deleted" from "RAT invalid").
func TestManage_Delete_HappyPath(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	created := f.register(t, nil)

	resp := f.manage(t, http.MethodDelete, created.registrationClientURI, created.registrationAccessToken, nil)
	t.Cleanup(func() { resp.Body.Close() })
	if resp.StatusCode != http.StatusNoContent {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 204 body=%s", resp.StatusCode, raw)
	}
	// Body must be empty (RFC 7592 §2.3).
	raw, _ := io.ReadAll(resp.Body)
	if len(raw) != 0 {
		t.Errorf("DELETE body must be empty, got %q", raw)
	}

	// Confirm the client is actually gone.
	if _, err := f.prov.Store.GetClient(context.Background(), created.clientID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("client lookup post-delete: want ErrNotFound, got %v", err)
	}

	// Subsequent GET / PUT / DELETE must all return 401 invalid_token.
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			var reqBody any
			if method == http.MethodPut {
				reqBody = minimalMetadata()
			}
			subResp := f.manage(t, method, created.registrationClientURI, created.registrationAccessToken, reqBody)
			defer subResp.Body.Close()
			if subResp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s status=%d want 401", method, subResp.StatusCode)
			}
		})
	}
}

// TestManage_Delete_AlreadyGone confirms re-deleting a client returns
// 401 (enumeration defence).
func TestManage_Delete_AlreadyGone(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	created := f.register(t, nil)
	// First delete succeeds.
	resp := f.manage(t, http.MethodDelete, created.registrationClientURI, created.registrationAccessToken, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("first delete status=%d want 204", resp.StatusCode)
	}
	// Second delete returns 401.
	again := f.manage(t, http.MethodDelete, created.registrationClientURI, created.registrationAccessToken, nil)
	defer again.Body.Close()
	if again.StatusCode != http.StatusUnauthorized {
		t.Errorf("second delete status=%d want 401", again.StatusCode)
	}
}

// TestManage_RoundTrip_PreservesOIDCProfile drives POST → GET → PUT → GET
// on a metadata payload that carries every OIDC profile field the
// library persists, asserting each value survives every hop intact. The
// regression target is the period when [store.Client] only carried the
// protocol-relevant fields, so RFC 7592 management requests echoed an
// empty client_name / logo_uri / contacts / etc. on subsequent reads.
func TestManage_RoundTrip_PreservesOIDCProfile(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

	rich := map[string]any{
		"redirect_uris":                []string{"https://rp.test.invalid/cb"},
		"client_name":                  "Round-Trip RP",
		"client_uri":                   "https://rp.test.invalid",
		"logo_uri":                     "https://rp.test.invalid/logo.png",
		"policy_uri":                   "https://rp.test.invalid/policy",
		"tos_uri":                      "https://rp.test.invalid/tos",
		"contacts":                     []string{"ops@rp.test.invalid"},
		"default_max_age":              float64(3600),
		"require_auth_time":            true,
		"default_acr_values":           []string{"urn:test:acr:loa1"},
		"initiate_login_uri":           "https://rp.test.invalid/start",
		"application_type":             "web",
		"subject_type":                 "public",
		"id_token_signed_response_alg": "ES256",
	}

	resp := f.post(t, rich, iat)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST status=%d want 201 body=%s", resp.StatusCode, raw)
	}
	created := decodeBody(t, resp)
	clientID, _ := created["client_id"].(string)
	rat, _ := created["registration_access_token"].(string)
	if clientID == "" || rat == "" {
		t.Fatalf("malformed POST response: %+v", created)
	}
	checkProfileFields(t, "POST", created, rich)

	// GET re-reads the persisted metadata — values must match the
	// original POST.
	getResp := f.manage(t, http.MethodGet, f.endpoint+"/"+clientID, rat, nil)
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET status=%d want 200", getResp.StatusCode)
	}
	checkProfileFields(t, "GET", decodeBody(t, getResp), rich)

	// PUT mutates a subset and asserts the unmutated fields still
	// round-trip.
	updated := map[string]any{
		"redirect_uris":                []string{"https://rp.test.invalid/cb-new"},
		"client_name":                  "Round-Trip RP (renamed)",
		"client_uri":                   rich["client_uri"],
		"logo_uri":                     rich["logo_uri"],
		"policy_uri":                   rich["policy_uri"],
		"tos_uri":                      rich["tos_uri"],
		"contacts":                     rich["contacts"],
		"default_max_age":              rich["default_max_age"],
		"require_auth_time":            rich["require_auth_time"],
		"default_acr_values":           rich["default_acr_values"],
		"initiate_login_uri":           rich["initiate_login_uri"],
		"application_type":             rich["application_type"],
		"subject_type":                 rich["subject_type"],
		"id_token_signed_response_alg": rich["id_token_signed_response_alg"],
	}
	putResp := f.manage(t, http.MethodPut, f.endpoint+"/"+clientID, rat, updated)
	defer putResp.Body.Close()
	if putResp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(putResp.Body)
		t.Fatalf("PUT status=%d want 200 body=%s", putResp.StatusCode, raw)
	}
	putBody := decodeBody(t, putResp)
	rotatedRAT, _ := putBody["registration_access_token"].(string)
	if rotatedRAT == "" || rotatedRAT == rat {
		t.Fatalf("PUT must rotate the RAT, before=%q after=%q", rat, rotatedRAT)
	}
	checkProfileFields(t, "PUT", putBody, updated)

	// Final GET under the rotated RAT confirms the persisted state
	// matches the PUT body.
	finalResp := f.manage(t, http.MethodGet, f.endpoint+"/"+clientID, rotatedRAT, nil)
	defer finalResp.Body.Close()
	if finalResp.StatusCode != http.StatusOK {
		t.Fatalf("final GET status=%d want 200", finalResp.StatusCode)
	}
	checkProfileFields(t, "final GET", decodeBody(t, finalResp), updated)
}

func TestManage_RoundTrip_PreservesExplicitZeroDefaultMaxAge(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

	body := map[string]any{
		"redirect_uris":   []string{"https://rp.test.invalid/cb"},
		"default_max_age": float64(0),
	}
	resp := f.post(t, body, iat)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST status=%d want 201 body=%s", resp.StatusCode, raw)
	}
	created := decodeBody(t, resp)
	if got, ok := created["default_max_age"]; !ok || got != float64(0) {
		t.Fatalf("POST default_max_age=%v present=%t want 0", got, ok)
	}
	clientID, _ := created["client_id"].(string)
	rat, _ := created["registration_access_token"].(string)

	getResp := f.manage(t, http.MethodGet, f.endpoint+"/"+clientID, rat, nil)
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(getResp.Body)
		t.Fatalf("GET status=%d want 200 body=%s", getResp.StatusCode, raw)
	}
	got := decodeBody(t, getResp)
	if v, ok := got["default_max_age"]; !ok || v != float64(0) {
		t.Fatalf("GET default_max_age=%v present=%t want 0", v, ok)
	}
}

// checkProfileFields asserts every key in want is present and equal in
// got. The helper uses reflect-style equality via JSON's any-typed
// values; numbers come back as float64 and slices as []any, so the
// table is built with those types in mind.
func checkProfileFields(tb testing.TB, label string, got, want map[string]any) {
	tb.Helper()
	for k, v := range want {
		gotV, ok := got[k]
		if !ok {
			tb.Errorf("%s: %s missing from response", label, k)
			continue
		}
		if !equalJSON(gotV, v) {
			tb.Errorf("%s: %s=%v want %v", label, k, gotV, v)
		}
	}
}

// equalJSON compares two values that decoded from JSON via the
// generic any path. It exists so the round-trip test can compare
// []string against []any without converting one to the other in
// every assertion.
func equalJSON(a, b any) bool {
	av, ok := a.([]any)
	if !ok {
		return a == b
	}
	switch bv := b.(type) {
	case []any:
		if len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !equalJSON(av[i], bv[i]) {
				return false
			}
		}
		return true
	case []string:
		if len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !equalJSON(av[i], bv[i]) {
				return false
			}
		}
		return true
	}
	return false
}

// TestManage_RoundTrip_PreservesBackchannelLogout pins the rule
// that `backchannel_logout_uri` and
// `backchannel_logout_session_required` MUST survive a POST →
// GET → PUT → GET round-trip. The check is wired through the
// existing [checkProfileFields] helper so a regression that drops
// the fields from `clientToResponse` or the response struct fails
// the same way other RFC 7592 round-trip rows do.
func TestManage_RoundTrip_PreservesBackchannelLogout(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	_, iat := f.issueIAT(t, op.InitialAccessTokenSpec{})

	original := map[string]any{
		"redirect_uris":                       []string{"https://rp.test.invalid/cb"},
		"backchannel_logout_uri":              "https://rp.test.invalid/logout",
		"backchannel_logout_session_required": true,
	}
	resp := f.post(t, original, iat)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST status=%d want 201 body=%s", resp.StatusCode, raw)
	}
	created := decodeBody(t, resp)
	clientID, _ := created["client_id"].(string)
	rat, _ := created["registration_access_token"].(string)
	if clientID == "" || rat == "" {
		t.Fatalf("malformed POST response: %+v", created)
	}
	checkProfileFields(t, "POST", created, original)

	getResp := f.manage(t, http.MethodGet, f.endpoint+"/"+clientID, rat, nil)
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("GET status=%d want 200", getResp.StatusCode)
	}
	checkProfileFields(t, "GET", decodeBody(t, getResp), original)

	// PUT a different logout endpoint and confirm the new value
	// (not the old one, and not an empty value) round-trips.
	updated := map[string]any{
		"redirect_uris":                       []string{"https://rp.test.invalid/cb"},
		"backchannel_logout_uri":              "https://rp.test.invalid/logout-v2",
		"backchannel_logout_session_required": true,
	}
	putResp := f.manage(t, http.MethodPut, f.endpoint+"/"+clientID, rat, updated)
	defer putResp.Body.Close()
	if putResp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(putResp.Body)
		t.Fatalf("PUT status=%d want 200 body=%s", putResp.StatusCode, raw)
	}
	putBody := decodeBody(t, putResp)
	rotatedRAT, _ := putBody["registration_access_token"].(string)
	if rotatedRAT == "" {
		t.Fatalf("PUT must rotate the RAT")
	}
	checkProfileFields(t, "PUT", putBody, updated)

	finalResp := f.manage(t, http.MethodGet, f.endpoint+"/"+clientID, rotatedRAT, nil)
	defer finalResp.Body.Close()
	if finalResp.StatusCode != http.StatusOK {
		t.Fatalf("final GET status=%d want 200", finalResp.StatusCode)
	}
	checkProfileFields(t, "final GET", decodeBody(t, finalResp), updated)
}

// TestManage_Update_RatPutFailureRollsBackMetadata pins the rule
// that when the rotated RAT cannot be persisted, the management
// update path MUST best-effort restore the prior client metadata so
// a partial write (new metadata + missing rotated RAT) never lands.
//
// The register-path symmetry is to delete the freshly inserted
// client; the management-path symmetry restores the existing
// snapshot via UpdateClient. Without the rollback the handler would
// surface 500 with the new metadata still in the registry, leaving
// the operator with a recovery puzzle the library could close on
// its own.
//
// The test uses a thin wrapper around [inmem.Store] that fails the
// next RAT Put once and then passes through. The choice to inject a
// failure via a wrapper (rather than a global flag) keeps the
// testkit-default store reusable so a parallel test suite cannot
// observe the failure.
func TestManage_Update_RatPutFailureRollsBackMetadata(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	wrap := &failingRATStore{Store: st, failNextPut: 1}
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	logBuf := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	prov := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithDynamicRegistration(op.RegistrationOption{}),
			op.WithStore(wrap),
			op.WithLogger(logger),
		),
	)
	f := &dcrFixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/register",
		clock:    clock,
		logBuf:   logBuf,
	}
	// Register a client first; the wrapper lets the initial RAT Put
	// through (failNextPut starts at 1 — the register path uses 1 RAT
	// Put, the management path uses another).
	wrap.failNextPut = 0 // permit POST /register
	created := f.register(t, map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
		"client_name":   "RAT Rollback Test Client",
	})
	wrap.failNextPut = 1 // arm failure for the next PUT

	// Snapshot the persisted metadata before the PUT.
	before, err := st.Clients().GetClient(context.Background(), created.clientID)
	if err != nil {
		t.Fatalf("FindByID(before): %v", err)
	}
	if before.ClientName != "RAT Rollback Test Client" {
		t.Fatalf("pre-PUT name=%q want %q", before.ClientName, "RAT Rollback Test Client")
	}

	// PUT a metadata change — the RAT Put will fail mid-flight.
	put := map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
		"client_name":   "Should Not Persist",
	}
	resp := f.manage(t, http.MethodPut, f.endpoint+"/"+created.clientID, created.registrationAccessToken, put)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 500 body=%s", resp.StatusCode, raw)
	}

	// The metadata MUST have been rolled back to the pre-PUT snapshot.
	after, err := st.Clients().GetClient(context.Background(), created.clientID)
	if err != nil {
		t.Fatalf("FindByID(after): %v", err)
	}
	if after.ClientName != before.ClientName {
		t.Errorf("post-rollback client_name=%q want %q (rollback did not restore prior metadata)",
			after.ClientName, before.ClientName)
	}
}

// failingRATStore wraps an [inmem.Store] and fails the next N RAT Put
// calls. The struct embeds *inmem.Store so every other substore
// passes through unchanged.
//
// failNextPut is read and decremented by the wrapped Put; tests set
// it to 0 to disarm the failure (the embedded inmem store's Put then
// runs normally).
type failingRATStore struct {
	*inmem.Store
	failNextPut int
}

// errInjected is the canned error the failing wrapper surfaces. The
// concrete value lets the handler's logger record a deterministic
// reason without the test having to inspect the wire body.
var errInjected = errors.New("injected RAT put failure")

func (s *failingRATStore) RegistrationAccessTokens() store.RegistrationAccessTokenStore {
	return &failingRATSubstore{inner: s.Store.RegistrationAccessTokens(), parent: s}
}

type failingRATSubstore struct {
	inner  store.RegistrationAccessTokenStore
	parent *failingRATStore
}

func (s *failingRATSubstore) Put(ctx context.Context, t *store.RegistrationAccessToken) error {
	if s.parent.failNextPut > 0 {
		s.parent.failNextPut--
		return errInjected
	}
	return s.inner.Put(ctx, t)
}

func (s *failingRATSubstore) GetByClientID(ctx context.Context, clientID string) (*store.RegistrationAccessToken, error) {
	return s.inner.GetByClientID(ctx, clientID)
}

func (s *failingRATSubstore) Delete(ctx context.Context, clientID string) error {
	return s.inner.Delete(ctx, clientID)
}

// TestRegister_ClientRegisterFailureDoesNotConsumeIAT pins the rule
// that when [Clients.RegisterClient] fails, the IAT MUST NOT be
// consumed. The IAT IncrementUses must not run ahead of credential
// generation or persistence; otherwise a transient crypto/rand or
// registry-write fault would produce "IAT used, no client".
//
// The test injects a one-shot failure into RegisterClient, drives a
// POST /register, and asserts the IAT's Uses counter is unchanged.
// A subsequent retry under the same IAT then succeeds — proving the
// IAT was preserved for the recovery path.
func TestRegister_ClientRegisterFailureDoesNotConsumeIAT(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	wrap := &failingRegisterStore{Store: st}
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	logBuf := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	prov := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithDynamicRegistration(op.RegistrationOption{}),
			op.WithStore(wrap),
			op.WithLogger(logger),
		),
	)
	f := &dcrFixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/register",
		clock:    clock,
		logBuf:   logBuf,
	}
	// Mint an IAT with MaxUses=1 so the test pins the "single-use"
	// invariant. Pre-fix the IAT was consumed by the failed register
	// and the retry got 401.
	issued, err := prov.OP.IssueInitialAccessToken(context.Background(), op.InitialAccessTokenSpec{MaxUses: 1})
	if err != nil {
		t.Fatalf("IssueInitialAccessToken: %v", err)
	}

	// Arm RegisterClient to fail once.
	wrap.failNext = 1
	resp := f.post(t, map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
	}, issued.Value)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("first POST status=%d want 500 body=%s", resp.StatusCode, raw)
	}

	// IAT MUST still be usable: retry without re-issuing.
	wrap.failNext = 0
	retry := f.post(t, map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
	}, issued.Value)
	defer retry.Body.Close()
	if retry.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(retry.Body)
		t.Fatalf("retry POST status=%d want 201 body=%s (IAT was burned by the failed register)",
			retry.StatusCode, raw)
	}
}

// failingRegisterStore wraps an [inmem.Store] and fails the next N
// RegisterClient calls.
type failingRegisterStore struct {
	*inmem.Store
	failNext int
}

func (s *failingRegisterStore) RegisterClient(ctx context.Context, c *store.Client) error {
	if s.failNext > 0 {
		s.failNext--
		return errInjected
	}
	return s.Store.RegisterClient(ctx, c)
}

// TestManage_Delete_CascadesAccessTokenRevocation pins the rule
// that DELETE /register/{client_id} MUST cascade through every
// substore that implements [store.RevokeByClient], including the
// JWT access-token registry and the opaque access-token store.
//
// The test seeds one record per substore directly, runs DELETE, and
// asserts every record is revoked afterwards. Refresh and grant
// cascades are covered by older tests; this test extends the matrix
// to AT / opaque AT so a regression that drops the new probe rows
// fails here.
func TestManage_Delete_CascadesAccessTokenRevocation(t *testing.T) {
	t.Parallel()

	f := newFixture(t, op.RegistrationOption{})
	created := f.register(t, nil)
	ctx := context.Background()

	// Seed an access-token registry row for the client.
	atRec := store.AccessTokenRecord{
		JTI:       "at-jti-1",
		GrantID:   "grant-1",
		Subject:   "user-1",
		ClientID:  created.clientID,
		IssuedAt:  f.clock.now,
		ExpiresAt: f.clock.now.Add(time.Hour),
	}
	if err := f.prov.Store.AccessTokens().Register(ctx, atRec); err != nil {
		t.Fatalf("AccessTokens.Register: %v", err)
	}

	// Seed an opaque access-token row for the client. The ID is the
	// raw (pre-hash) value the inmem store hashes internally before
	// indexing — Find / RevokeByID accept the same raw form.
	oat := &store.OpaqueAccessToken{
		ID:        "oat-1",
		ClientID:  created.clientID,
		Subject:   "user-1",
		IssuedAt:  f.clock.now,
		ExpiresAt: f.clock.now.Add(time.Hour),
	}
	if err := f.prov.Store.OpaqueAccessTokens().Save(ctx, oat); err != nil {
		t.Fatalf("OpaqueAccessTokens.Save: %v", err)
	}

	// DELETE the client.
	resp := f.manage(t, http.MethodDelete, created.registrationClientURI, created.registrationAccessToken, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("DELETE status=%d want 204 body=%s", resp.StatusCode, raw)
	}

	// JWT AT registry row must be revoked.
	gotAT, err := f.prov.Store.AccessTokens().Find(ctx, atRec.JTI)
	if err != nil {
		t.Fatalf("AccessTokens.Find: %v", err)
	}
	if gotAT == nil {
		t.Fatal("AT row vanished — expected revoked-but-present (inmem mark-revoked semantics)")
	}
	if !gotAT.Revoked {
		t.Errorf("AT row revoked=%v want true (cascade did not reach AccessTokens)", gotAT.Revoked)
	}

	// Opaque AT row must be revoked.
	gotOAT, err := f.prov.Store.OpaqueAccessTokens().Find(ctx, oat.ID)
	if err != nil {
		t.Fatalf("OpaqueAccessTokens.Find: %v", err)
	}
	if gotOAT == nil {
		t.Fatal("opaque AT row vanished — expected revoked-but-present")
	}
	if !gotOAT.Revoked {
		t.Errorf("opaque AT row revoked=%v want true (cascade did not reach OpaqueAccessTokens)", gotOAT.Revoked)
	}
}

// TestManage_Delete_ClientDeleteFailureRetainsRATForRetry pins the
// invariant that when DELETE /register/{client_id} fails because
// the client record cannot be removed (transient store fault), the
// RAT MUST remain valid so the RP can retry. The reverse order
// would strand the client behind a 500 with no path back to the
// management endpoint.
func TestManage_Delete_ClientDeleteFailureRetainsRATForRetry(t *testing.T) {
	t.Parallel()

	st := inmem.New()
	wrap := &failingClientStore{Store: st}
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	logBuf := &syncBuffer{}
	logger := slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	prov := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithDynamicRegistration(op.RegistrationOption{}),
			op.WithStore(wrap),
			op.WithLogger(logger),
		),
	)
	f := &dcrFixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/register",
		clock:    clock,
		logBuf:   logBuf,
	}
	created := f.register(t, map[string]any{
		"redirect_uris": []string{"https://rp.test.invalid/cb"},
	})

	// Arm the failure for DeleteClient.
	wrap.failNextDelete = 1
	resp := f.manage(t, http.MethodDelete, f.endpoint+"/"+created.clientID, created.registrationAccessToken, nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 500 body=%s", resp.StatusCode, raw)
	}

	// The client record MUST still exist (delete failed).
	if _, err := st.Clients().GetClient(context.Background(), created.clientID); err != nil {
		t.Fatalf("client should still exist after failed delete: %v", err)
	}
	// The RAT MUST still exist so the RP can retry the management
	// call. Pre-fix the RAT was removed before the client delete.
	rat, err := st.RegistrationAccessTokens().GetByClientID(context.Background(), created.clientID)
	if err != nil {
		t.Fatalf("RAT should still exist for retry: %v", err)
	}
	if rat == nil || rat.ClientID != created.clientID {
		t.Fatalf("RAT lookup returned %+v want non-nil for client %q", rat, created.clientID)
	}

	// A retry (with the failure disarmed) MUST succeed using the same RAT.
	wrap.failNextDelete = 0
	retry := f.manage(t, http.MethodDelete, f.endpoint+"/"+created.clientID, created.registrationAccessToken, nil)
	defer retry.Body.Close()
	if retry.StatusCode != http.StatusNoContent {
		raw, _ := io.ReadAll(retry.Body)
		t.Fatalf("retry status=%d want 204 body=%s", retry.StatusCode, raw)
	}
}

// failingClientStore wraps an [inmem.Store] and fails the next N
// DeleteClient calls. The library obtains the writable
// [store.ClientRegistry] view by asserting on the entire Store
// (see [op.resolveClientRegistry]), so embedding the inmem store
// here exposes RegisterClient / UpdateClient / DeleteClient directly
// — the wrapper only needs to override DeleteClient.
type failingClientStore struct {
	*inmem.Store
	failNextDelete int
}

// DeleteClient overrides the embedded [inmem.Store] method so the
// next failNextDelete invocations return [errInjected]. After the
// counter drains the call passes through to the in-memory store so
// the test can verify retry semantics under the same wrapper.
func (s *failingClientStore) DeleteClient(ctx context.Context, id string) error {
	if s.failNextDelete > 0 {
		s.failNextDelete--
		return errInjected
	}
	return s.Store.DeleteClient(ctx, id)
}

// TestManage_NotAllowedMethods rejects non-GPDP verbs with 405.
func TestManage_NotAllowedMethods(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodPost, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t, op.RegistrationOption{})
			created := f.register(t, nil)
			req, err := http.NewRequestWithContext(context.Background(), method, created.registrationClientURI, http.NoBody)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Authorization", "Bearer "+created.registrationAccessToken)
			resp, err := f.prov.HTTPClient(nil).Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusMethodNotAllowed {
				t.Errorf("status=%d want 405", resp.StatusCode)
			}
			if got := resp.Header.Get("Allow"); got != "GET, PUT, DELETE" {
				t.Errorf("Allow=%q want \"GET, PUT, DELETE\"", got)
			}
		})
	}
}
