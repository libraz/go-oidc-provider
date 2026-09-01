package endsession

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
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

// findFailingSessionStore fails the read half of the session store on
// demand. It is the counterpart of [failingSessionStore], which fails
// the write half: the two halves of a logout have independent failure
// modes, and a fix that only teaches the handler about one of them
// leaves the other reporting a sign-out that never happened.
type findFailingSessionStore struct {
	store.SessionStore
	mu  sync.Mutex
	err error
}

// arm makes every subsequent Find fail with err. The store starts
// healthy so a session can be issued and its cookie sealed before the
// fault is introduced, which is the sequence a real outage follows.
func (s *findFailingSessionStore) arm(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.err = err
}

func (s *findFailingSessionStore) Find(ctx context.Context, id string) (*store.Session, error) {
	s.mu.Lock()
	err := s.err
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return s.SessionStore.Find(ctx, id)
}

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
	now := time.Now()
	plan, err := manager.PlanEstablishment(context.Background(), sessions.EstablishPlan{
		Login: sessions.Login{
			Subject:  "subject-1",
			AuthTime: now,
		},
		StableSessionID:      "stable-session",
		StableChooserGroupID: "stable-chooser",
		Now:                  now,
	})
	if err != nil {
		t.Fatalf("Manager.PlanEstablishment: %v", err)
	}
	outcome, err := manager.Establish(context.Background(), plan)
	if err != nil {
		t.Fatalf("Manager.Establish: %v", err)
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
	if err := terminateSession(w, req, deps, readSessionLookup(req, deps)); err == nil {
		t.Fatal("termination reported success although the session row was not deleted")
	}

	if !recorder.has("session.destroy_failed") {
		t.Fatalf("session.destroy_failed not emitted: %#v", recorder.snapshot())
	}
	if recorder.has("session.destroyed") {
		t.Fatalf("session.destroyed emitted despite store failure: %#v", recorder.snapshot())
	}
	// The cookie stays. It is the browser's only handle on the session
	// that is still running, so retiring it would leave the user unable
	// to retry the logout the OP just failed to perform.
	for _, c := range w.Result().Cookies() {
		if c.Name == cookie.SessionProfile.Name {
			t.Fatal("session cookie retired although the session it names was not deleted")
		}
	}
}

// TestServe_ConfirmedPOSTDuringSessionReadFaultDoesNotClaimSignOut is
// the read-side counterpart of
// [TestTerminateSession_AuditsSessionStoreFailureWithoutFalseSuccess].
// The request is the one that used to be most dangerous: a POST that
// passes the double-submit CSRF gate, so nothing else stands between it
// and the response. When the store cannot answer the session read, the
// OP knows neither which session to end nor whether one exists, and the
// only honest answer is a failure — a signed-out page here would tell
// the user their session is gone while the row and the subject's tokens
// are still live.
func TestServe_ConfirmedPOSTDuringSessionReadFaultDoesNotClaimSignOut(t *testing.T) {
	t.Parallel()

	backend := inmem.New()
	sessionStore := &findFailingSessionStore{SessionStore: backend.Sessions()}
	manager, outcome := issueManagerSession(t, sessionStore)
	sessionStore.arm(errors.New("session backend unavailable"))

	recorder := &recordingAudit{}
	handler := Handler(Deps{
		Issuer:   "https://op.example.com",
		Sessions: manager,
		Audit:    recorder,
	})
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, confirmedLogoutPOST(outcome.Cookie))
	resp := w.Result()

	if resp.StatusCode/100 == 2 {
		t.Fatalf("status = %d, want a failure status: the OP never learned whether a session exists", resp.StatusCode)
	}
	if !recorder.has("session.destroy_failed") {
		t.Fatalf("session.destroy_failed not emitted: %#v", recorder.snapshot())
	}
	// The counter an operator watches for "logouts that did not happen"
	// is fed by the catalogue projection of that event name, so pin the
	// projection here rather than re-testing the metrics bridge.
	definition, ok := auditevent.Lookup("session.destroy_failed")
	if !ok || definition.Metric != auditevent.MetricLogoutFailures {
		t.Fatalf("session.destroy_failed projects onto %v, want MetricLogoutFailures", definition.Metric)
	}
	if recorder.has("session.destroyed") || recorder.has("session.already_absent") {
		t.Fatalf("unreadable session recorded as destroyed or absent: %#v", recorder.snapshot())
	}
	for _, c := range resp.Cookies() {
		if c.Name == cookie.SessionProfile.Name {
			t.Fatal("session cookie retired although the session it names may still be live")
		}
	}
}

// confirmedLogoutPOST builds the POST the interstitial itself submits:
// same-origin, carrying both halves of the double-submit CSRF token and
// the scope fingerprint the confirmation form binds. Every gate before
// the session read admits it, which is what makes it the right probe
// for what happens after the read.
func confirmedLogoutPOST(sessionCookie string) *http.Request {
	form := url.Values{
		confirmTokenField:          {"csrf-token"},
		"logout_scope_fingerprint": {logoutScopeAll},
	}
	req := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		"https://op.example.com/end_session",
		strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://op.example.com")
	req.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessionCookie})
	req.AddCookie(&http.Cookie{Name: cookie.LogoutCSRFProfile.Name, Value: "csrf-token"})
	return req
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
	terminateSession(httptest.NewRecorder(), req, deps, readSessionLookup(req, deps))

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
	terminateSession(httptest.NewRecorder(), req, deps, readSessionLookup(req, deps))
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
