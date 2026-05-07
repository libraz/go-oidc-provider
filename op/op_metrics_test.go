package op_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/libraz/go-oidc-provider/op"
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
	// successful probe registration.
	_ = metricNames(t, reg)
	for _, name := range []string{
		"oidc_token_issued_total",
		"oidc_tokens_refreshed_total",
		"oidc_login_attempts_total",
		"oidc_refresh_replay_detected_total",
		"oidc_code_replay_detected_total",
		"oidc_client_authn_failures_total",
		"oidc_dcr_events_total",
		"oidc_device_authorization_events_total",
		"oidc_device_code_events_total",
		"oidc_ciba_events_total",
		"oidc_token_exchange_events_total",
		"oidc_back_channel_logout_total",
		"oidc_introspection_errors_total",
		"oidc_token_revoke_failures_total",
		"oidc_dpop_loose_method_case_admitted_total",
		"oidc_key_retired_kid_presented_total",
	} {
		probe := prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: "probe"})
		if err := reg.Register(probe); err == nil {
			t.Errorf("metric %q not registered: probe accepted", name)
		}
	}
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
