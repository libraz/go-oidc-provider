package metrics_test

import (
	"context"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/metrics"
)

// recordingEmitter is a test stub that captures every event it
// receives. The mutex makes the table-driven concurrency check below
// reliable on -race.
type recordingEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recordingEmitter) Emit(_ context.Context, ev audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *recordingEmitter) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]audit.Event, len(r.events))
	copy(out, r.events)
	return out
}

// counterValue scans families for the metric with the matching name
// and label set, returning its current value. The helper isolates the
// dto.Metric inspection loop from the assertion sites below.
func counterValue(t *testing.T, families []*dto.MetricFamily, name string, labels map[string]string) float64 {
	t.Helper()
	for _, fam := range families {
		if fam.GetName() != name {
			continue
		}
		for _, m := range fam.GetMetric() {
			if labelsMatch(m.GetLabel(), labels) {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func labelsMatch(have []*dto.LabelPair, want map[string]string) bool {
	if len(have) != len(want) {
		return false
	}
	for _, lp := range have {
		if want[lp.GetName()] != lp.GetValue() {
			return false
		}
	}
	return true
}

// newTestCollector builds a collector against a fresh registry and
// returns both. The registry is the surface every test inspects via
// Gather; the collector is the bridge target.
func newTestCollector(t *testing.T, opts metrics.Options) (*metrics.Collector, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	c, err := metrics.New(reg, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, reg
}

func TestBridge_TokenIssued_StaticClientLabelEmitted(t *testing.T) {
	t.Parallel()

	c, reg := newTestCollector(t, metrics.Options{
		StaticClientIDs: map[string]struct{}{"client-1": {}},
	})
	rec := &recordingEmitter{}
	b := metrics.NewBridge(c, rec)

	b.Emit(context.Background(), audit.Event{
		Name:     "token.issued",
		ClientID: "client-1",
		Extras:   map[string]any{"grant_type": "authorization_code"},
	})

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	got := counterValue(t, families, "oidc_token_issued_total", map[string]string{
		"grant_type": "authorization_code",
		"client_id":  "client-1",
	})
	if got != 1 {
		t.Fatalf("counter = %v, want 1", got)
	}
	if len(rec.snapshot()) != 1 {
		t.Fatalf("downstream emitter saw %d events, want 1", len(rec.snapshot()))
	}
}

func TestBridge_TokenIssued_DynamicClientCollapsesToEmpty(t *testing.T) {
	t.Parallel()

	c, reg := newTestCollector(t, metrics.Options{
		StaticClientIDs: map[string]struct{}{"client-1": {}},
	})
	b := metrics.NewBridge(c, nil)

	b.Emit(context.Background(), audit.Event{
		Name:     "token.issued",
		ClientID: "dynamic-99",
		Extras:   map[string]any{"grant_type": "authorization_code"},
	})

	families, _ := reg.Gather()
	got := counterValue(t, families, "oidc_token_issued_total", map[string]string{
		"grant_type": "authorization_code",
		"client_id":  "",
	})
	if got != 1 {
		t.Fatalf("counter = %v, want 1", got)
	}
	leaked := counterValue(t, families, "oidc_token_issued_total", map[string]string{
		"grant_type": "authorization_code",
		"client_id":  "dynamic-99",
	})
	if leaked != 0 {
		t.Fatalf("dynamic client_id leaked into label: counter = %v", leaked)
	}
}

func TestBridge_LoginAttempts_TableDriven(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		event      audit.Event
		wantResult string
		wantAuth   string
	}{
		{
			name: "success_with_authenticator",
			event: audit.Event{
				Name:   "login.success",
				Extras: map[string]any{"authenticator": "password"},
			},
			wantResult: "success",
			wantAuth:   "password",
		},
		{
			name: "failed_with_authenticator",
			event: audit.Event{
				Name:   "login.failed",
				Extras: map[string]any{"authenticator": "totp"},
			},
			wantResult: "failed",
			wantAuth:   "totp",
		},
		{
			name: "success_without_extras",
			event: audit.Event{
				Name: "login.success",
			},
			wantResult: "success",
			wantAuth:   "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, reg := newTestCollector(t, metrics.Options{})
			b := metrics.NewBridge(c, nil)
			b.Emit(context.Background(), tc.event)

			families, _ := reg.Gather()
			got := counterValue(t, families, "oidc_login_attempts_total", map[string]string{
				"result":        tc.wantResult,
				"authenticator": tc.wantAuth,
			})
			if got != 1 {
				t.Fatalf("counter = %v, want 1", got)
			}
		})
	}
}

func TestBridge_ReplayCounters(t *testing.T) {
	t.Parallel()

	c, reg := newTestCollector(t, metrics.Options{})
	b := metrics.NewBridge(c, nil)

	b.Emit(context.Background(), audit.Event{Name: "refresh.replay_detected"})
	b.Emit(context.Background(), audit.Event{Name: "code.replay_detected"})

	families, _ := reg.Gather()
	for _, name := range []string{
		"oidc_refresh_replay_detected_total",
		"oidc_code_replay_detected_total",
	} {
		got := counterValue(t, families, name, map[string]string{})
		if got != 1 {
			t.Errorf("%s = %v, want 1", name, got)
		}
	}
}

func TestBridge_UnrelatedEvent_ForwardedWithoutMetric(t *testing.T) {
	t.Parallel()

	c, reg := newTestCollector(t, metrics.Options{})
	rec := &recordingEmitter{}
	b := metrics.NewBridge(c, rec)

	b.Emit(context.Background(), audit.Event{Name: "account.created"})

	families, _ := reg.Gather()
	for _, fam := range families {
		for _, m := range fam.GetMetric() {
			if m.GetCounter().GetValue() != 0 {
				t.Errorf("metric %s saw a mutation it should not have", fam.GetName())
			}
		}
	}
	if len(rec.snapshot()) != 1 {
		t.Fatalf("downstream emitter saw %d events, want 1", len(rec.snapshot()))
	}
	if rec.snapshot()[0].Name != "account.created" {
		t.Fatalf("forwarded event = %q, want account.created", rec.snapshot()[0].Name)
	}
}

func TestBridge_NilNext_AcceptsAndDoesNotPanic(t *testing.T) {
	t.Parallel()

	c, _ := newTestCollector(t, metrics.Options{})
	b := metrics.NewBridge(c, nil)

	b.Emit(context.Background(), audit.Event{Name: "refresh.replay_detected"})
	// reaching here without panic is the assertion; the discard
	// downstream is internal so there is nothing else to inspect.
}
