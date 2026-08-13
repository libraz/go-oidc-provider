package op_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// metricNames returns the set of metric names registered on reg. The
// helper is used by the assertions below to confirm the curated
// metric set is wired without depending on any sample existing on
// the vec metrics yet (vec metrics are only surfaced by Gather once
// they receive a sample).
func metricNames(t *testing.T, reg *prometheus.Registry) map[string]struct{} {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	out := make(map[string]struct{}, len(families))
	for _, fam := range families {
		out[fam.GetName()] = struct{}{}
	}
	return out
}

func TestProvider_WithoutPrometheus_NoMetricsRegistered(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	_, base := startProvider(t)

	// Issue any request to confirm the unwrapped path still serves.
	resp := httpGet(t, base+"/.well-known/openid-configuration")
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := metricNames(t, reg); len(got) != 0 {
		t.Fatalf("expected zero metrics on the embedder registry, got %d", len(got))
	}
}

func TestProvider_WithPrometheus_RegistersCuratedMetrics(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	provider, err := op.New(append(validBaseOpts(t), op.WithPrometheus(reg))...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	t.Cleanup(srv.Close)

	resp := httpGet(t, srv.URL+"/.well-known/openid-configuration")
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	// Counters with no sample yet are not surfaced by Gather; the
	// probe-registration pattern below is the canonical way to assert
	// the registry is holding each curated counter. Any regression
	// that drops a metric from the constructor surfaces here as a
	// successful probe registration. The names come from the event
	// catalog, so a counter added there is asserted at this boundary
	// without the list being restated.
	_ = metricNames(t, reg)
	for _, name := range auditevent.MetricNames() {
		probe := prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: "probe"})
		if err := reg.Register(probe); err == nil {
			t.Errorf("metric %q not registered: probe accepted", name)
		}
	}
}

// TestProvider_WithPrometheus_TokenIssuedLabelsTheRedeemingGrant drives a
// real device-code redemption and asserts the first refresh token it
// mints is counted under its own grant. The counter is the operator's
// per-grant issuance signal, so a redemption filed under
// authorization_code both invents authorization-code issuance that never
// happened and hides the device flow entirely.
func TestProvider_WithPrometheus_TokenIssuedLabelsTheRedeemingGrant(t *testing.T) {
	t.Parallel()

	const clientID = "device-rp"
	const clientSecret = "device-rp-secret"

	secretHash, err := op.HashClientSecret(clientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	st := inmem.New()
	if err := st.RegisterClient(context.Background(), &store.Client{
		ID:                      clientID,
		SecretHash:              secretHash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes: []string{
			"urn:ietf:params:oauth:grant-type:device_code",
			"refresh_token",
		},
		Scopes: []string{"openid"},
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	reg := prometheus.NewRegistry()
	provider, err := op.New(append(validBaseOptsWithStore(t, st),
		op.WithDeviceCodeGrant(),
		op.WithPrometheus(reg),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewServer(provider)
	t.Cleanup(srv.Close)

	deviceAuth := url.Values{}
	deviceAuth.Set("scope", "openid")
	body := postForm(t, srv.URL+"/oidc/device_authorization", clientID, clientSecret, deviceAuth)
	deviceCode, _ := body["device_code"].(string)
	if deviceCode == "" {
		t.Fatalf("/device_authorization body missing device_code: %v", body)
	}
	if err := st.DeviceCodes().Approve(context.Background(), deviceCode, "user-1", time.Now().UTC()); err != nil {
		t.Fatalf("DeviceCodes.Approve: %v", err)
	}

	tokenReq := url.Values{}
	tokenReq.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	tokenReq.Set("device_code", deviceCode)
	tokens := postForm(t, srv.URL+"/oidc/token", clientID, clientSecret, tokenReq)
	if refreshToken, _ := tokens["refresh_token"].(string); refreshToken == "" {
		t.Fatalf("/token issued no refresh token, so the counter under test cannot move: %v", tokens)
	}

	issued := tokenIssuedByGrantType(t, reg)
	if issued["device_code"] != 1 {
		t.Errorf("oidc_token_issued_total{grant_type=\"device_code\"} = %v, want 1 (all: %v)",
			issued["device_code"], issued)
	}
	if got := issued["authorization_code"]; got != 0 {
		t.Errorf("device-code redemption counted as authorization_code: %v", got)
	}
}

// postForm sends a form-encoded, basic-authenticated POST and returns
// the decoded JSON body. Any non-200 response fails the test: every
// caller below is on a happy path where a protocol error would only
// surface later as an unexplained zero counter.
func postForm(t *testing.T, endpoint, clientID, clientSecret string, form url.Values) map[string]any {
	t.Helper()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest %s: %v", endpoint, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", endpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var decoded map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode %s body: %v", endpoint, err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST %s status = %d, body = %v", endpoint, resp.StatusCode, decoded)
	}
	return decoded
}

// tokenIssuedByGrantType reduces oidc_token_issued_total to a
// grant_type-keyed total. Folding the other labels away keeps the
// assertion on the dimension under test.
func tokenIssuedByGrantType(t *testing.T, reg *prometheus.Registry) map[string]float64 {
	t.Helper()

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	out := make(map[string]float64)
	for _, family := range families {
		if family.GetName() != "oidc_token_issued_total" {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetName() == "grant_type" {
					out[label.GetValue()] += metric.GetCounter().GetValue()
				}
			}
		}
	}
	return out
}

func TestProvider_WithPrometheus_NilRegistryRejected(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithPrometheus(nil))...)
	if err == nil {
		t.Fatal("expected error for nil registry, got nil")
	}
	if !op.IsServerError(err) {
		t.Fatalf("err = %v, want server-class configuration error", err)
	}
}
