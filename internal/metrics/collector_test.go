package metrics_test

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/libraz/go-oidc-provider/internal/metrics"
)

// expectedCollectorNames is the closed list of metric names the
// constructor MUST register on a fresh registry. Adding a new metric
// here without updating the constructor (or vice versa) surfaces a
// regression at test time.
var expectedCollectorNames = []string{
	"oidc_token_issued_total",
	"oidc_login_attempts_total",
	"oidc_refresh_replay_detected_total",
	"oidc_code_replay_detected_total",
}

func TestCollector_New_NilRegistryRejected(t *testing.T) {
	t.Parallel()

	_, err := metrics.New(nil, metrics.Options{})
	if err == nil {
		t.Fatal("expected error for nil registry, got nil")
	}
}

func TestCollector_New_RegistersExpectedMetrics(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	if _, err := metrics.New(reg, metrics.Options{}); err != nil {
		t.Fatalf("New: %v", err)
	}

	// Re-registering a same-named descriptor on the registry MUST be
	// refused — either with AlreadyRegisteredError (when the labels
	// match) or with a description-mismatch error (when they do not).
	// The assertion below confirms each expected metric is held by
	// the registry without depending on a non-zero observation
	// existing yet (vec metrics are not surfaced by Gather until they
	// receive at least one sample).
	for _, name := range expectedCollectorNames {
		probe := prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: "probe"})
		if err := reg.Register(probe); err == nil {
			t.Errorf("metric %q not registered: probe accepted", name)
		}
	}
}

func TestCollector_New_DoubleRegistrationSurfacesAlreadyRegistered(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	if _, err := metrics.New(reg, metrics.Options{}); err != nil {
		t.Fatalf("first New: %v", err)
	}
	_, err := metrics.New(reg, metrics.Options{})
	if err == nil {
		t.Fatal("expected error on second registration, got nil")
	}
	var already prometheus.AlreadyRegisteredError
	if !errors.As(err, &already) {
		t.Fatalf("err type = %T, want AlreadyRegisteredError", err)
	}
}
