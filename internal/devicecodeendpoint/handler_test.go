package devicecodeendpoint_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/devicecode"
	"github.com/libraz/go-oidc-provider/internal/devicecodeendpoint"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func TestHandlerIssuesDeviceAuthorizationRecord(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	st, deps := newFixture(t, now, store.Client{
		ID:                      "device-client",
		PublicClient:            true,
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{grant.DeviceCode.String()},
		Scopes:                  []string{"openid", "profile", "offline_access"},
		Resources:               []string{"https://api.example"},
	})
	deps.DeviceCodeTTL = 10 * time.Minute
	deps.PollInterval = 7 * time.Second
	deps.VerificationURI = "https://login.example/activate"

	rec := postForm(t, deps, url.Values{
		"client_id": {"device-client"},
		"scope":     {"openid profile"},
		"resource":  {"HTTPS://API.EXAMPLE/"},
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	assertNoStore(t, rec.Result())
	if ct := rec.Result().Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", ct)
	}

	var body struct {
		DeviceCode              string `json:"device_code"`
		UserCode                string `json:"user_code"`
		VerificationURI         string `json:"verification_uri"`
		VerificationURIComplete string `json:"verification_uri_complete"`
		ExpiresIn               int64  `json:"expires_in"`
		Interval                int64  `json:"interval"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode success response: %v", err)
	}
	if body.DeviceCode == "" || body.UserCode == "" {
		t.Fatalf("success response missing codes: %+v", body)
	}
	if body.VerificationURI != "https://login.example/activate" {
		t.Fatalf("verification_uri = %q", body.VerificationURI)
	}
	wantComplete := "https://login.example/activate?user_code=" + url.QueryEscape(body.UserCode)
	if body.VerificationURIComplete != wantComplete {
		t.Fatalf("verification_uri_complete = %q, want %q", body.VerificationURIComplete, wantComplete)
	}
	if body.ExpiresIn != int64((10 * time.Minute).Seconds()) {
		t.Fatalf("expires_in = %d, want 600", body.ExpiresIn)
	}
	if body.Interval != 7 {
		t.Fatalf("interval = %d, want 7", body.Interval)
	}

	persisted, err := st.DeviceCodes().FindByDeviceCode(context.Background(), body.DeviceCode)
	if err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
	if persisted.ClientID != "device-client" {
		t.Fatalf("ClientID = %q, want device-client", persisted.ClientID)
	}
	if !slices.Equal(persisted.Scope, []string{"openid", "profile"}) {
		t.Fatalf("Scope = %v, want [openid profile]", persisted.Scope)
	}
	if !slices.Equal(persisted.Resource, []string{"https://api.example"}) {
		t.Fatalf("Resource = %v, want [https://api.example]", persisted.Resource)
	}
	if persisted.Status != store.DeviceCodeStatusPending {
		t.Fatalf("Status = %v, want pending", persisted.Status)
	}
	if !persisted.IssuedAt.Equal(now) {
		t.Fatalf("IssuedAt = %v, want %v", persisted.IssuedAt, now)
	}
	if !persisted.ExpiresAt.Equal(now.Add(10 * time.Minute)) {
		t.Fatalf("ExpiresAt = %v, want %v", persisted.ExpiresAt, now.Add(10*time.Minute))
	}
	if persisted.Interval != 7*time.Second {
		t.Fatalf("Interval = %v, want 7s", persisted.Interval)
	}
}

func TestHandlerAppliesDeviceAuthorizationDefaults(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	st, deps := newFixture(t, now, store.Client{
		ID:                      "device-client",
		PublicClient:            true,
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{grant.DeviceCode.String()},
		Scopes:                  []string{"openid", "profile"},
	})

	rec := postForm(t, deps, url.Values{"client_id": {"device-client"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := decodeSuccess(t, rec)
	if body.VerificationURI != "https://issuer.example/device" {
		t.Fatalf("verification_uri = %q, want issuer-derived /device URI", body.VerificationURI)
	}
	if body.ExpiresIn != int64(devicecode.DefaultExpiresIn.Seconds()) {
		t.Fatalf("expires_in = %d, want %d", body.ExpiresIn, int64(devicecode.DefaultExpiresIn.Seconds()))
	}
	if body.Interval != int64(devicecode.DefaultInterval.Seconds()) {
		t.Fatalf("interval = %d, want %d", body.Interval, int64(devicecode.DefaultInterval.Seconds()))
	}

	persisted, err := st.DeviceCodes().FindByDeviceCode(context.Background(), body.DeviceCode)
	if err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
	if !slices.Equal(persisted.Scope, []string{"openid", "profile"}) {
		t.Fatalf("default Scope = %v, want full registered scope", persisted.Scope)
	}
}

func TestHandlerAcceptsClientSecretPostForConfidentialClient(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	st, deps := newFixture(t, now, store.Client{
		ID:                      "confidential-device",
		TokenEndpointAuthMethod: string(clientauth.MethodSecretPost),
		SecretHash:              "stored-secret-digest",
		GrantTypes:              []string{grant.DeviceCode.String()},
		Scopes:                  []string{"openid"},
	})
	deps.SecretVerifier = exactSecretVerifier{
		wantPresented: "correct-secret",
		wantStored:    "stored-secret-digest",
	}

	rec := postForm(t, deps, url.Values{
		"client_id":     {"confidential-device"},
		"client_secret": {"correct-secret"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	body := decodeSuccess(t, rec)
	if _, err := st.DeviceCodes().FindByDeviceCode(context.Background(), body.DeviceCode); err != nil {
		t.Fatalf("FindByDeviceCode: %v", err)
	}
}

func TestHandlerRejectsConfidentialClientAuthFailures(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	_, deps := newFixture(t, now, store.Client{
		ID:                      "confidential-device",
		TokenEndpointAuthMethod: string(clientauth.MethodSecretPost),
		SecretHash:              "stored-secret-digest",
		GrantTypes:              []string{grant.DeviceCode.String()},
		Scopes:                  []string{"openid"},
	})
	deps.SecretVerifier = exactSecretVerifier{
		wantPresented: "correct-secret",
		wantStored:    "stored-secret-digest",
	}

	t.Run("wrong secret", func(t *testing.T) {
		t.Parallel()

		rec := postForm(t, deps, url.Values{
			"client_id":     {"confidential-device"},
			"client_secret": {"wrong-secret"},
		})
		assertOAuthError(t, rec, http.StatusUnauthorized, "invalid_client")
	})

	t.Run("method disallowed by endpoint policy", func(t *testing.T) {
		t.Parallel()

		local := deps
		local.AllowedClientAuthMethods = []clientauth.Method{clientauth.MethodNone}
		rec := postForm(t, local, url.Values{
			"client_id":     {"confidential-device"},
			"client_secret": {"correct-secret"},
		})
		assertOAuthError(t, rec, http.StatusUnauthorized, "invalid_client")
	})
}

func TestHandlerRejectsMalformedRequestsBeforeIssuance(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	_, deps := newFixture(t, now, store.Client{
		ID:                      "device-client",
		PublicClient:            true,
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{grant.DeviceCode.String()},
		Scopes:                  []string{"openid"},
	})

	t.Run("get method", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodGet, "/device_authorization", nil)
		rec := httptest.NewRecorder()
		devicecodeendpoint.Handler(deps).ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("status = %d, want 405", rec.Code)
		}
		if allow := rec.Result().Header.Get("Allow"); allow != http.MethodPost {
			t.Fatalf("Allow = %q, want POST", allow)
		}
		assertNoStore(t, rec.Result())
	})

	t.Run("wrong content type", func(t *testing.T) {
		t.Parallel()

		req := httptest.NewRequest(http.MethodPost, "/device_authorization", strings.NewReader("client_id=device-client"))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		devicecodeendpoint.Handler(deps).ServeHTTP(rec, req)
		assertOAuthError(t, rec, http.StatusBadRequest, "invalid_request")
	})

	t.Run("duplicate single valued parameter", func(t *testing.T) {
		t.Parallel()

		rec := postForm(t, deps, url.Values{
			"client_id": {"device-client", "device-client"},
		})
		assertOAuthError(t, rec, http.StatusBadRequest, "invalid_request")
	})
}

func TestHandlerRejectsPolicyViolations(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

	t.Run("client not registered for device grant", func(t *testing.T) {
		t.Parallel()

		_, deps := newFixture(t, now, store.Client{
			ID:                      "device-client",
			PublicClient:            true,
			TokenEndpointAuthMethod: "none",
			GrantTypes:              []string{grant.AuthorizationCode.String()},
			Scopes:                  []string{"openid"},
		})
		rec := postForm(t, deps, url.Values{"client_id": {"device-client"}})
		assertOAuthError(t, rec, http.StatusBadRequest, "unauthorized_client")
	})

	t.Run("requested scope not in client allowlist", func(t *testing.T) {
		t.Parallel()

		_, deps := newFixture(t, now, store.Client{
			ID:                      "device-client",
			PublicClient:            true,
			TokenEndpointAuthMethod: "none",
			GrantTypes:              []string{grant.DeviceCode.String()},
			Scopes:                  []string{"openid"},
		})
		rec := postForm(t, deps, url.Values{
			"client_id": {"device-client"},
			"scope":     {"openid email"},
		})
		assertOAuthError(t, rec, http.StatusBadRequest, "invalid_scope")
	})

	t.Run("scope restricted to another client", func(t *testing.T) {
		t.Parallel()

		_, deps := newFixture(t, now, store.Client{
			ID:                      "device-client",
			PublicClient:            true,
			TokenEndpointAuthMethod: "none",
			GrantTypes:              []string{grant.DeviceCode.String()},
			Scopes:                  []string{"admin"},
		})
		deps.Scopes = scoperegistry.New([]scoperegistry.Entry{
			{Name: "admin", AllowedClients: []string{"admin-console"}},
		})
		rec := postForm(t, deps, url.Values{
			"client_id": {"device-client"},
			"scope":     {"admin"},
		})
		assertOAuthError(t, rec, http.StatusBadRequest, "invalid_scope")
	})

	t.Run("unregistered resource", func(t *testing.T) {
		t.Parallel()

		_, deps := newFixture(t, now, store.Client{
			ID:                      "device-client",
			PublicClient:            true,
			TokenEndpointAuthMethod: "none",
			GrantTypes:              []string{grant.DeviceCode.String()},
			Scopes:                  []string{"openid"},
			Resources:               []string{"https://api.example"},
		})
		rec := postForm(t, deps, url.Values{
			"client_id": {"device-client"},
			"resource":  {"https://other.example"},
		})
		assertOAuthError(t, rec, http.StatusBadRequest, "invalid_target")
	})

	t.Run("multiple resources unsupported", func(t *testing.T) {
		t.Parallel()

		_, deps := newFixture(t, now, store.Client{
			ID:                      "device-client",
			PublicClient:            true,
			TokenEndpointAuthMethod: "none",
			GrantTypes:              []string{grant.DeviceCode.String()},
			Scopes:                  []string{"openid"},
			Resources:               []string{"https://api.example", "https://other.example"},
		})
		rec := postForm(t, deps, url.Values{
			"client_id": {"device-client"},
			"resource":  {"https://api.example", "https://other.example"},
		})
		assertOAuthError(t, rec, http.StatusBadRequest, "invalid_target")
	})

	t.Run("sender constraint required", func(t *testing.T) {
		t.Parallel()

		_, deps := newFixture(t, now, store.Client{
			ID:                      "device-client",
			PublicClient:            true,
			TokenEndpointAuthMethod: "none",
			GrantTypes:              []string{grant.DeviceCode.String()},
			Scopes:                  []string{"openid"},
		})
		deps.RequireSenderConstraint = true
		rec := postForm(t, deps, url.Values{"client_id": {"device-client"}})
		assertOAuthError(t, rec, http.StatusBadRequest, "invalid_request")
	})
}

func TestHandlerRejectsMissingDeviceCodeStoreAsServerMisconfiguration(t *testing.T) {
	t.Parallel()

	deps := devicecodeendpoint.Deps{
		Issuer: "https://issuer.example",
	}
	rec := postForm(t, deps, url.Values{"client_id": {"device-client"}})
	assertOAuthError(t, rec, http.StatusInternalServerError, "server_error")
}

type fixedClock time.Time

func (c fixedClock) Now() time.Time { return time.Time(c) }

func newFixture(tb testing.TB, now time.Time, client store.Client) (*inmem.Store, devicecodeendpoint.Deps) {
	tb.Helper()

	st := inmem.New(inmem.WithClock(fixedClock(now)))
	if err := st.RegisterClient(context.Background(), &client); err != nil {
		tb.Fatalf("RegisterClient: %v", err)
	}
	scopes := make([]scoperegistry.Entry, 0, len(client.Scopes))
	for _, s := range client.Scopes {
		scopes = append(scopes, scoperegistry.Entry{Name: s, Public: true})
	}
	return st, devicecodeendpoint.Deps{
		Issuer:      "https://issuer.example/",
		Clients:     st.Clients(),
		DeviceCodes: st.DeviceCodes(),
		Scopes:      scoperegistry.New(scopes),
		Clock:       fixedClock(now),
	}
}

func postForm(tb testing.TB, deps devicecodeendpoint.Deps, form url.Values) *httptest.ResponseRecorder {
	tb.Helper()

	req := httptest.NewRequest(http.MethodPost, "/device_authorization", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	devicecodeendpoint.Handler(deps).ServeHTTP(rec, req)
	return rec
}

type successBody struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

func decodeSuccess(tb testing.TB, rec *httptest.ResponseRecorder) successBody {
	tb.Helper()

	var body successBody
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		tb.Fatalf("decode success response: %v", err)
	}
	return body
}

func assertOAuthError(tb testing.TB, rec *httptest.ResponseRecorder, status int, code string) {
	tb.Helper()

	if rec.Code != status {
		tb.Fatalf("status = %d, want %d; body = %s", rec.Code, status, rec.Body.String())
	}
	assertNoStore(tb, rec.Result())
	var body struct {
		Error string `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		raw, _ := io.ReadAll(rec.Result().Body)
		tb.Fatalf("decode error body: %v; raw=%q", err, raw)
	}
	if body.Error != code {
		tb.Fatalf("error = %q, want %q; body=%s", body.Error, code, rec.Body.String())
	}
}

type exactSecretVerifier struct {
	wantPresented string
	wantStored    string
}

func (v exactSecretVerifier) Verify(presented, stored string) error {
	if presented != v.wantPresented || stored != v.wantStored {
		return clientauth.ErrCredentialsInvalid
	}
	return nil
}

func assertNoStore(tb testing.TB, res *http.Response) {
	tb.Helper()

	if got := res.Header.Get("Cache-Control"); got != "no-store" {
		tb.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := res.Header.Get("Pragma"); got != "no-cache" {
		tb.Fatalf("Pragma = %q, want no-cache", got)
	}
}
