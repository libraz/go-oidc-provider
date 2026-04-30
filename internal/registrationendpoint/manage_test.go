package registrationendpoint_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
)

// dcrCreated bundles the result of a successful POST /register so
// management tests can drive GET / PUT / DELETE without re-registering
// every time.
type dcrCreated struct {
	clientID                string
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
	resp, err := http.DefaultClient.Do(req)
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

// TestManage_Update_RejectsClientIDOverride confirms attempting to
// change client_id via the body is a 400 invalid_client_metadata.
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
	if got["error"] != "invalid_client_metadata" {
		t.Errorf("error=%v want invalid_client_metadata", got["error"])
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
			resp, err := http.DefaultClient.Do(req)
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
