package metrics_test

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/metrics"
)

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
	if _, err := metrics.New(reg, metrics.Options{Issuer: testIssuer}); err != nil {
		t.Fatalf("New: %v", err)
	}

	// Re-registering a same-named descriptor on the registry MUST be
	// refused — either with AlreadyRegisteredError (when the labels
	// match) or with a description-mismatch error (when they do not).
	// The assertion below confirms each expected metric is held by
	// the registry without depending on a non-zero observation
	// existing yet (vec metrics are not surfaced by Gather until they
	// receive at least one sample).
	for _, name := range auditevent.MetricNames() {
		probe := prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: "probe"})
		if err := reg.Register(probe); err == nil {
			t.Errorf("metric %q not registered: probe accepted", name)
		}
	}
}

func TestCollector_TokenRevokeFailuresHelpCoversAllStages(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	c, err := metrics.New(reg, metrics.Options{Issuer: testIssuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	metrics.NewBridge(c, nil).Emit(context.Background(), audit.Event{
		Name: "refresh.prior_access_token_revoke_failed",
	})
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() != "oidc_token_revoke_failures_total" {
			continue
		}
		const want = "Token-revocation side-effect failures, partitioned by failed stage (token, refresh chain, refresh grant, or prior access token)."
		if family.GetHelp() != want {
			t.Fatalf("Help=%q want %q", family.GetHelp(), want)
		}
		return
	}
	t.Fatal("oidc_token_revoke_failures_total family missing")
}

func TestCollector_New_DoubleRegistrationSurfacesAlreadyRegistered(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	if _, err := metrics.New(reg, metrics.Options{Issuer: testIssuer}); err != nil {
		t.Fatalf("first New: %v", err)
	}
	_, err := metrics.New(reg, metrics.Options{Issuer: testIssuer})
	if err == nil {
		t.Fatal("expected error on second registration, got nil")
	}
	var already prometheus.AlreadyRegisteredError
	if !errors.As(err, &already) {
		t.Fatalf("err type = %T, want AlreadyRegisteredError", err)
	}
}

func TestCollector_UnregisterIsIdempotentAndOwnsOnlyItsCollectors(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	c, err := metrics.New(reg, metrics.Options{Issuer: testIssuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !c.Unregister() {
		t.Fatal("first Unregister returned false")
	}
	if c.Unregister() {
		t.Fatal("second Unregister returned true")
	}
	if _, err := metrics.New(reg, metrics.Options{Issuer: testIssuer}); err != nil {
		t.Fatalf("New after cleanup: %v", err)
	}

	// A collector registered by another owner survives cleanup of c.
	otherReg := prometheus.NewRegistry()
	other := prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "oidc_refresh_replay_detected_total",
		Help:        "other owner",
		ConstLabels: prometheus.Labels{"issuer": "other"},
	})
	if err := otherReg.Register(other); err != nil {
		t.Fatalf("register other owner: %v", err)
	}
	otherCollector, err := metrics.New(otherReg, metrics.Options{Issuer: testIssuer})
	if err == nil {
		otherCollector.Unregister()
		t.Fatal("expected collision with the other owner's collector")
	}
	if !otherReg.Unregister(other) {
		t.Fatal("other owner's collector was removed or unavailable")
	}
}

// TestCollector_New_DistinctIssuersShareRegistry asserts two OPs can
// point at one registry: the issuer constant label separates their
// series without the metric names changing.
func TestCollector_New_DistinctIssuersShareRegistry(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	if _, err := metrics.New(reg, metrics.Options{Issuer: "https://first.example.test"}); err != nil {
		t.Fatalf("first New: %v", err)
	}
	if _, err := metrics.New(reg, metrics.Options{Issuer: "https://second.example.test"}); err != nil {
		t.Fatalf("second New: %v", err)
	}
}

// TestCollector_New_IssuerConstLabelEmitted asserts the issuer rides on
// the emitted samples, not just on the descriptor.
func TestCollector_New_IssuerConstLabelEmitted(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	c, err := metrics.New(reg, metrics.Options{Issuer: testIssuer})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	metrics.NewBridge(c, nil).Emit(context.Background(), audit.Event{Name: "refresh.replay_detected"})

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	var found bool
	for _, fam := range families {
		if fam.GetName() != "oidc_refresh_replay_detected_total" {
			continue
		}
		for _, m := range fam.GetMetric() {
			for _, lp := range m.GetLabel() {
				if lp.GetName() != "issuer" {
					continue
				}
				found = true
				if lp.GetValue() != testIssuer {
					t.Errorf("issuer label = %q, want %q", lp.GetValue(), testIssuer)
				}
			}
		}
	}
	if !found {
		t.Fatal("no issuer label on the emitted sample")
	}
}

// TestCollector_New_RollbackOnPartialRegistration asserts a rejected
// collector leaves the registry exactly as it was found. The blocker
// replicates the last metric the constructor registers, so the failure
// lands after every earlier collector was accepted — and each of those
// must be undone.
//
// The proof is the second New: once the blocker is withdrawn the
// registry holds nothing of ours, so a clean run must succeed. Any
// collector left behind by the failed run surfaces there as an
// AlreadyRegisteredError. A same-name probe cannot serve as the proof
// instead: the registry keeps its name-to-dimension map for its whole
// lifetime, so a probe is refused on the recorded dimensions whether or
// not the collector itself is still registered.
func TestCollector_New_RollbackOnPartialRegistration(t *testing.T) {
	t.Parallel()

	const colliding = "oidc_key_retired_kid_presented_total"

	reg := prometheus.NewRegistry()
	blocker := prometheus.NewCounter(prometheus.CounterOpts{
		Name:        colliding,
		Help:        collidingMetricHelp(t, colliding),
		ConstLabels: prometheus.Labels{"issuer": testIssuer},
	})
	if err := reg.Register(blocker); err != nil {
		t.Fatalf("register blocker: %v", err)
	}

	_, err := metrics.New(reg, metrics.Options{Issuer: testIssuer})
	if err == nil {
		t.Fatal("expected New to fail against the pre-registered collider, got nil")
	}
	var already prometheus.AlreadyRegisteredError
	if !errors.As(err, &already) {
		t.Fatalf("err type = %T, want AlreadyRegisteredError", err)
	}

	// Scalar counters are surfaced by Gather even without a sample, so
	// the registry contents are directly observable: only the blocker's
	// family may remain.
	families, gatherErr := reg.Gather()
	if gatherErr != nil {
		t.Fatalf("Gather: %v", gatherErr)
	}
	for _, fam := range families {
		if fam.GetName() != colliding {
			t.Errorf("metric family %q survived the failed registration", fam.GetName())
		}
	}

	if !reg.Unregister(blocker) {
		t.Fatal("blocker was not registered at withdrawal time")
	}
	if _, err := metrics.New(reg, metrics.Options{Issuer: testIssuer}); err != nil {
		t.Fatalf("New on the rolled-back registry: %v", err)
	}
}

// collidingMetricHelp returns the help string the constructor attaches
// to name, read back off a throwaway registry. Deriving it keeps the
// blocker's descriptor identical to the real one without the test
// restating the help text, which would otherwise drift.
func collidingMetricHelp(t *testing.T, name string) string {
	t.Helper()
	reg := prometheus.NewRegistry()
	if _, err := metrics.New(reg, metrics.Options{Issuer: testIssuer}); err != nil {
		t.Fatalf("New: %v", err)
	}
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, fam := range families {
		if fam.GetName() == name {
			return fam.GetHelp()
		}
	}
	t.Fatalf("metric %q not surfaced by Gather", name)
	return ""
}
