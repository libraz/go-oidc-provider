package endsession_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/backchannel"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/endsession"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/op/store"
)

// fanOutLiveness is a liveness guard, not a latency assertion. Each
// test releases its blocked deliverer before waiting on it, so the
// wait resolves as soon as the goroutine is scheduled; the bound only
// keeps a regression from hanging until the package timeout.
const fanOutLiveness = 5 * time.Second

// errDeliveryRefused stands in for a relying party that answers the
// logout POST with a rejection.
var errDeliveryRefused = errors.New("rp refused the logout token")

// drainFanOut blocks until the coordinator's detached fan-outs have
// finished. Tests call it before reading anything the fan-out
// goroutine wrote, since the drain is what establishes the
// happens-before edge.
func drainFanOut(t *testing.T, coord *backchannel.Coordinator) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), fanOutLiveness)
	defer cancel()
	if err := coord.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
}

// concurrentAuditRecorder is the emitter the detached fan-out writes
// to. It locks because the records now arrive from a goroutine other
// than the one running the test.
type concurrentAuditRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *concurrentAuditRecorder) Emit(_ context.Context, ev audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *concurrentAuditRecorder) snapshot() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]audit.Event, len(r.events))
	copy(out, r.events)
	return out
}

func (r *concurrentAuditRecorder) find(name string) *audit.Event {
	for _, ev := range r.snapshot() {
		if ev.Name == name {
			return &ev
		}
	}
	return nil
}

// detachHarness extends the shared end-session harness with a
// back-channel coordinator whose deliverer the test controls.
type detachHarness struct {
	*harness
	coord   *backchannel.Coordinator
	audit   *concurrentAuditRecorder
	handler http.Handler
}

// newDetachHarness mounts /end_session against a coordinator wired to
// deliver, and seeds one relying party that registered a
// backchannel_logout_uri for the harness subject.
func newDetachHarness(t *testing.T, deliver backchannel.Deliverer) *detachHarness {
	t.Helper()
	h := newHarness(t)

	const rpClient = "rp-detached"
	if err := h.store.RegisterClient(context.Background(), &store.Client{
		ID:                   rpClient,
		BackchannelLogoutURI: "https://rp-detached.example/logout",
	}); err != nil {
		t.Fatalf("RegisterClient(%s): %v", rpClient, err)
	}
	if err := h.store.Grants().Save(context.Background(), &store.Grant{
		ID:        "grant-detached",
		Subject:   "user-1",
		ClientID:  rpClient,
		CreatedAt: h.clock.now,
		UpdatedAt: h.clock.now,
	}); err != nil {
		t.Fatalf("Grants().Save: %v", err)
	}

	keyEntry, err := keys.GenerateES256("detach-1")
	if err != nil {
		t.Fatalf("keys.GenerateES256: %v", err)
	}
	rec := &concurrentAuditRecorder{}
	coord, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer:    "https://op.example.com",
		Signing:   backchannel.SigningKey{KeyID: keyEntry.KeyID, Signer: keyEntry.Signer},
		Clients:   h.store.Clients(),
		Grants:    h.store.Grants().(store.GrantClientLister),
		Deliverer: deliver,
		Emitter:   rec,
		Clock:     h.clock,
	})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}

	deps := h.deps
	deps.Backchannel = coord
	deps.Audit = rec
	mux := http.NewServeMux()
	mux.Handle(h.endSessionPath, endsession.Handler(deps))
	return &detachHarness{harness: h, coord: coord, audit: rec, handler: mux}
}

// confirmToken runs the interstitial GET and returns the double-submit
// CSRF token the confirmation POST has to carry.
func (h *detachHarness) confirmToken(t *testing.T, cookieValue string) string {
	t.Helper()
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, h.endSessionPath, http.NoBody,
	)
	req.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()
	tok := readConfirmCookie(resp)
	if tok == "" {
		t.Fatal("interstitial GET did not set the confirmation cookie")
	}
	return tok
}

// confirmLogout dispatches the confirmation POST that terminates the
// session and hands the fan-out to the coordinator.
func (h *detachHarness) confirmLogout(t *testing.T, cookieValue, token string) *http.Response {
	t.Helper()
	form := url.Values{"logout_csrf": {token}}
	req := httptest.NewRequestWithContext(
		context.Background(), http.MethodPost, h.endSessionPath, strings.NewReader(form.Encode()),
	)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "op.example.com"
	req.Header.Set("Origin", "https://op.example.com")
	req.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: cookieValue})
	req.AddCookie(&http.Cookie{Name: "__Host-oidc_logout_csrf", Value: token})
	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, req)
	return w.Result()
}

// TestHandler_StalledBackchannelTargetDoesNotHoldTheLogoutResponse is
// the core property: a relying party that accepts the connection and
// then never answers must not keep the end-user's /end_session request
// open. The deliverer here blocks until the test releases it, so a
// handler that waited for delivery would never produce a response.
//
// The same request also proves the ordering the user is owed: by the
// time the response is written the OP-side session is already gone, so
// the OP never reports "logged out" over a session that is still live.
// Both assertions run while the delivery is still wedged.
func TestHandler_StalledBackchannelTargetDoesNotHoldTheLogoutResponse(t *testing.T) {
	t.Parallel()

	entered := make(chan struct{})
	release := make(chan struct{})
	deliver := backchannel.DelivererFunc(func(context.Context, backchannel.Target, string) error {
		close(entered)
		<-release
		return nil
	})
	h := newDetachHarness(t, deliver)
	cookieValue, sessionID := h.issueSession(t)
	token := h.confirmToken(t, cookieValue)

	responses := make(chan *http.Response, 1)
	//nolint:bodyclose // the receiver below owns the body and closes it.
	go func() { responses <- h.confirmLogout(t, cookieValue, token) }()

	select {
	case <-entered:
	case <-time.After(fanOutLiveness):
		t.Fatal("back-channel delivery never started")
	}

	var resp *http.Response
	select {
	case resp = <-responses:
	case <-time.After(fanOutLiveness):
		t.Fatal("/end_session did not answer while a back-channel target was stalled")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}

	// Still inside the stalled delivery: the session must already be
	// unusable, and the audit trail must say so.
	if active, err := h.sessionMgr.Resolve(context.Background(), cookieValue); err == nil && active != nil {
		t.Fatalf("session %s still resolves after the logout response was written", sessionID)
	}
	if h.audit.find("session.destroyed") == nil {
		t.Fatalf("session.destroyed not emitted before the response: %#v", h.audit.snapshot())
	}

	close(release)
	drainFanOut(t, h.coord)
	if h.audit.find("logout.back_channel.delivered") == nil {
		t.Fatalf("detached delivery outcome not audited: %#v", h.audit.snapshot())
	}
}

// TestHandler_DetachedDeliveryFailureStaysObservable covers what
// detaching gave up: the handler no longer sees the fan-out outcome,
// so the audit chain is the only thing that can report a relying party
// the OP failed to notify. The record carries the client and the
// cause, and it reaches the same emitter the handler's own events use,
// which is what feeds the back-channel logout metric.
func TestHandler_DetachedDeliveryFailureStaysObservable(t *testing.T) {
	t.Parallel()

	deliver := backchannel.DelivererFunc(func(context.Context, backchannel.Target, string) error {
		return errDeliveryRefused
	})
	h := newDetachHarness(t, deliver)
	cookieValue, sessionID := h.issueSession(t)
	token := h.confirmToken(t, cookieValue)

	resp := h.confirmLogout(t, cookieValue, token)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	drainFanOut(t, h.coord)

	ev := h.audit.find("logout.back_channel.failed")
	if ev == nil {
		t.Fatalf("detached delivery failure not audited: %#v", h.audit.snapshot())
	}
	if ev.ClientID != "rp-detached" {
		t.Errorf("failure event client_id=%q want rp-detached", ev.ClientID)
	}
	if ev.SessionID != sessionID {
		t.Errorf("failure event session_id=%q want %q", ev.SessionID, sessionID)
	}
	if got, _ := ev.Extras["error"].(string); !strings.Contains(got, errDeliveryRefused.Error()) {
		t.Errorf("failure event error=%q does not carry the delivery cause", got)
	}
}
