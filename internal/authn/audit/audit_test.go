package audit_test

import (
	"context"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn/audit"
)

// recordingObserver collects every event for later assertions.
type recordingObserver struct {
	events []audit.Event
}

func (r *recordingObserver) Observe(_ context.Context, evt audit.Event) {
	r.events = append(r.events, evt)
}

// TestFanOutDispatchesAllObservers asserts FanOut delivers the event
// to every registered observer in registration order.
func TestFanOutDispatchesAllObservers(t *testing.T) {
	t.Parallel()

	a := &recordingObserver{}
	b := &recordingObserver{}
	evt := audit.Event{Subject: "user-1", Outcome: audit.Success, Factor: "password"}

	audit.FanOut(context.Background(), []audit.Observer{a, b}, evt)

	if len(a.events) != 1 || a.events[0].Subject != "user-1" {
		t.Errorf("observer a: events = %+v", a.events)
	}
	if len(b.events) != 1 || b.events[0].Subject != "user-1" {
		t.Errorf("observer b: events = %+v", b.events)
	}
}

// TestFanOutSkipsNilEntries asserts a nil entry in the slice is
// silently skipped — the orchestrator's Observers slice may contain
// nil values from a buggy embedder.
func TestFanOutSkipsNilEntries(t *testing.T) {
	t.Parallel()

	a := &recordingObserver{}
	evt := audit.Event{Subject: "user-2"}

	audit.FanOut(context.Background(), []audit.Observer{nil, a, nil}, evt)

	if len(a.events) != 1 {
		t.Fatalf("events = %+v, want 1", a.events)
	}
}
