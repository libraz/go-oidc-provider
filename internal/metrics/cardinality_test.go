package metrics_test

import (
	"context"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/metrics"
)

// labelAllowlist is the closed set of label names the OP is permitted
// to emit. A new label name appearing on any registered metric MUST
// be added here on purpose; until it is, the regression assertion
// below fails so the cardinality posture is reviewed before the
// label lands in production scrapes.
var labelAllowlist = map[string]struct{}{
	"grant_type":    {},
	"client_id":     {},
	"result":        {},
	"authenticator": {},
}

func TestCardinality_LabelAllowlist(t *testing.T) {
	t.Parallel()

	reg := prometheus.NewRegistry()
	c, err := metrics.New(reg, metrics.Options{
		StaticClientIDs: map[string]struct{}{"client-1": {}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Drive every emission path so every metric has at least one
	// sample for Gather to surface. The synthetic high-cardinality
	// values below would slip into labels if a future change forgot
	// to gate them through the static / known maps.
	bridge := metrics.NewBridge(c, nil)
	for _, ev := range []audit.Event{
		{
			Name:     "token.issued",
			ClientID: "dynamic-deadbeef-1234",
			Extras: map[string]any{
				"grant_type": "authorization_code",
				"sub":        "user-abc",
				"ip":         "203.0.113.7",
			},
		},
		{
			Name:     "login.success",
			ClientID: "dynamic-deadbeef-1234",
			ActorID:  "user-xyz",
			Extras:   map[string]any{"authenticator": "password"},
		},
		{
			Name:   "login.failed",
			Extras: map[string]any{"authenticator": "totp"},
		},
		{Name: "refresh.replay_detected"},
		{Name: "code.replay_detected"},
	} {
		bridge.Emit(context.Background(), ev)
	}

	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, fam := range families {
		for _, m := range fam.GetMetric() {
			for _, lp := range m.GetLabel() {
				name := lp.GetName()
				if _, ok := labelAllowlist[name]; !ok {
					t.Errorf("metric %s carries label %q outside the allowlist", fam.GetName(), name)
				}
			}
		}
	}
}
