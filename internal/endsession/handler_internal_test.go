package endsession

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/backchannel"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// recordingAudit collects the events under assertion. It locks because
// the back-channel fan-out is detached from the request, so its
// records arrive from a goroutine other than the one driving the
// handler.
type recordingAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recordingAudit) Emit(_ context.Context, event audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

func (r *recordingAudit) has(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, event := range r.events {
		if event.Name == name {
			return true
		}
	}
	return false
}

func (r *recordingAudit) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]audit.Event, len(r.events))
	copy(out, r.events)
	return out
}

type failingSessionStore struct {
	store.SessionStore
	err error
}

func (s failingSessionStore) Delete(context.Context, string) error { return s.err }

type failingGrantStore struct {
	store.GrantStore
	err error
}

type failingClientStore struct{ err error }

func (s failingClientStore) GetClient(context.Context, string) (*store.Client, error) {
	return nil, s.err
}

func (s failingGrantStore) ListBySubject(context.Context, string) ([]*store.Grant, error) {
	return nil, s.err
}

func issueManagerSession(t *testing.T, sessionsStore store.SessionStore) (*sessions.Manager, sessions.Outcome) {
	t.Helper()
	codec, err := cookie.NewCodec(make([]byte, 32))
	if err != nil {
		t.Fatalf("cookie.NewCodec: %v", err)
	}
	sessionCodec, err := sessions.NewCodec(codec)
	if err != nil {
		t.Fatalf("sessions.NewCodec: %v", err)
	}
	manager, err := sessions.NewManager(sessions.Config{
		Codec: sessionCodec,
		Store: sessionsStore,
		Clock: time.Now,
	})
	if err != nil {
		t.Fatalf("sessions.NewManager: %v", err)
	}
	outcome, err := manager.Issue(context.Background(), sessions.Login{
		Subject:  "subject-1",
		AuthTime: time.Now(),
	})
	if err != nil {
		t.Fatalf("Manager.Issue: %v", err)
	}
	return manager, outcome
}

func logoutRequest(cookieValue string) *http.Request {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "https://op.example.com/end_session", nil)
	req.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
	return req
}

func TestTerminateSession_AuditsSessionStoreFailureWithoutFalseSuccess(t *testing.T) {
	t.Parallel()

	boom := errors.New("session backend unavailable")
	backend := inmem.New()
	manager, outcome := issueManagerSession(t, failingSessionStore{
		SessionStore: backend.Sessions(),
		err:          boom,
	})
	recorder := &recordingAudit{}
	w := httptest.NewRecorder()
	req := logoutRequest(outcome.Cookie)
	deps := Deps{Sessions: manager, Audit: recorder}
	terminateSession(w, req, deps, readSessionFingerprint(req, deps))

	if !recorder.has("session.destroy_failed") {
		t.Fatalf("session.destroy_failed not emitted: %#v", recorder.snapshot())
	}
	if recorder.has("session.destroyed") {
		t.Fatalf("session.destroyed emitted despite store failure: %#v", recorder.snapshot())
	}
	if len(w.Result().Cookies()) == 0 {
		t.Fatal("logout did not clear the session cookie after store failure")
	}
}

func TestTerminateSession_AuditsTokenRevocationFailure(t *testing.T) {
	t.Parallel()

	boom := errors.New("grant backend unavailable")
	backend := inmem.New()
	manager, outcome := issueManagerSession(t, backend.Sessions())
	recorder := &recordingAudit{}
	req := logoutRequest(outcome.Cookie)
	deps := Deps{
		Sessions: manager,
		Grants: failingGrantStore{
			GrantStore: backend.Grants(),
			err:        boom,
		},
		Audit: recorder,
	}
	terminateSession(httptest.NewRecorder(), req, deps, readSessionFingerprint(req, deps))

	if !recorder.has("session.destroyed") {
		t.Fatalf("session.destroyed not emitted: %#v", recorder.snapshot())
	}
	if !recorder.has("logout.token_revoke_failed") {
		t.Fatalf("logout.token_revoke_failed not emitted: %#v", recorder.snapshot())
	}
}

func TestTerminateSession_ClientLookupFaultReachesBackchannelAudit(t *testing.T) {
	t.Parallel()

	boom := errors.New("client registry unavailable")
	backend := inmem.New()
	manager, outcome := issueManagerSession(t, backend.Sessions())
	now := time.Date(2026, 7, 24, 8, 0, 0, 0, time.UTC)
	if err := backend.Grants().Save(context.Background(), &store.Grant{
		ID: "grant-rp", Subject: "subject-1", ClientID: "rp-fault",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("save grant: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	recorder := &recordingAudit{}
	coordinator, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer:  "https://op.example.com",
		Signing: backchannel.SigningKey{KeyID: "sig-1", Signer: key},
		Clients: failingClientStore{err: boom},
		Grants:  backend.Grants().(store.GrantClientLister),
		Emitter: recorder,
	})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}

	req := logoutRequest(outcome.Cookie)
	deps := Deps{
		Sessions:    manager,
		Backchannel: coordinator,
		Audit:       recorder,
	}
	terminateSession(httptest.NewRecorder(), req, deps, readSessionFingerprint(req, deps))
	// The fan-out is detached from the request, so the evidence lands
	// after terminateSession has returned.
	drainCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := coordinator.Drain(drainCtx); err != nil {
		t.Fatalf("Drain: %v", err)
	}

	if !recorder.has("logout.back_channel.failed") {
		t.Fatalf("per-client failure evidence not emitted: %#v", recorder.snapshot())
	}
	if !recorder.has("logout.back_channel.resolve_failed") {
		t.Fatalf("aggregate resolution failure not emitted: %#v", recorder.snapshot())
	}
}
