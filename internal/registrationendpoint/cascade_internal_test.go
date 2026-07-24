package registrationendpoint

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
)

type cascadeFailureStore struct {
	err error
}

func (s cascadeFailureStore) RevokeByClient(context.Context, string) error {
	return s.err
}

type cascadeAuditRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *cascadeAuditRecorder) Emit(_ context.Context, event audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

func (r *cascadeAuditRecorder) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.events...)
}

func TestProbeRevokeByClient_FailureEmitsCatalogEvent(t *testing.T) {
	t.Parallel()

	recorder := &cascadeAuditRecorder{}
	injected := errors.New("injected cascade failure")
	probeRevokeByClient(
		context.Background(),
		Deps{Audit: recorder},
		"client-1",
		cascadeFailureStore{err: injected},
		auditevent.AuditDCRCascadeGrantRevokeFailed,
	)

	events := recorder.snapshot()
	if len(events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(events))
	}
	event := events[0]
	if event.Name != string(auditevent.AuditDCRCascadeGrantRevokeFailed) {
		t.Errorf("event name = %q, want %q", event.Name, auditevent.AuditDCRCascadeGrantRevokeFailed)
	}
	if event.ClientID != "client-1" {
		t.Errorf("client_id = %q, want client-1", event.ClientID)
	}
	if event.Level != audit.LevelError {
		t.Errorf("level = %v, want error", event.Level)
	}
	if event.Extras["error"] != injected.Error() {
		t.Errorf("error extra = %v, want %q", event.Extras["error"], injected)
	}
}
