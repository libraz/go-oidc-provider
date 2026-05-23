package metrics

import (
	"context"
	"sync"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/audit"
)

type bridgeRecordingEmitter struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *bridgeRecordingEmitter) Emit(_ context.Context, ev audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *bridgeRecordingEmitter) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.events)
}

func TestBridge_ForwardsWhenMetricUpdatePanics(t *testing.T) {
	t.Parallel()

	rec := &bridgeRecordingEmitter{}
	b := &Bridge{
		c:    &Collector{},
		next: rec,
	}

	b.Emit(context.Background(), audit.Event{Name: "refresh.replay_detected"})
	if rec.count() != 1 {
		t.Fatalf("forwarded events = %d, want 1", rec.count())
	}
}
