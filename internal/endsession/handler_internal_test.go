package endsession

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

type recordingAudit struct{ events []audit.Event }

func (r *recordingAudit) Emit(_ context.Context, event audit.Event) {
	r.events = append(r.events, event)
}

func (r *recordingAudit) has(name string) bool {
	for _, event := range r.events {
		if event.Name == name {
			return true
		}
	}
	return false
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
	terminateSession(w, logoutRequest(outcome.Cookie), Deps{Sessions: manager, Audit: recorder})

	if !recorder.has("session.destroy_failed") {
		t.Fatalf("session.destroy_failed not emitted: %#v", recorder.events)
	}
	if recorder.has("session.destroyed") {
		t.Fatalf("session.destroyed emitted despite store failure: %#v", recorder.events)
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
	terminateSession(httptest.NewRecorder(), logoutRequest(outcome.Cookie), Deps{
		Sessions: manager,
		Grants: failingGrantStore{
			GrantStore: backend.Grants(),
			err:        boom,
		},
		Audit: recorder,
	})

	if !recorder.has("session.destroyed") {
		t.Fatalf("session.destroyed not emitted: %#v", recorder.events)
	}
	if !recorder.has("logout.token_revoke_failed") {
		t.Fatalf("logout.token_revoke_failed not emitted: %#v", recorder.events)
	}
}
