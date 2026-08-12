package backchannel_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/backchannel"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// drainTimeout is a liveness guard, not a latency assertion: every
// test below releases its blocked deliverer (or hands the fan-out an
// already-elapsed budget) before draining, so the wait resolves as
// soon as the goroutine is scheduled. The bound only exists so a
// regression that leaves a fan-out wedged fails the test instead of
// hanging until the package timeout.
const drainTimeout = 5 * time.Second

// drain blocks until every detached fan-out has finished. Draining is
// also what establishes the happens-before edge a test needs before it
// reads values the fan-out goroutine wrote.
func drain(t *testing.T, coord *backchannel.Coordinator) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()
	if err := coord.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
}

// findEvent returns the first recorded event with the given name, or
// nil when the fan-out never emitted one.
func findEvent(events []audit.Event, name string) *audit.Event {
	for i := range events {
		if events[i].Name == name {
			return &events[i]
		}
	}
	return nil
}

// seedTarget registers one RP with a back-channel logout URI plus the
// grant that makes it part of subject's audience.
func seedTarget(t *testing.T, st *inmem.Store, clientID, logoutURI string) {
	t.Helper()
	now := time.Date(2026, 7, 24, 8, 0, 0, 0, time.UTC)
	saveClient(t, st, &store.Client{ID: clientID, BackchannelLogoutURI: logoutURI})
	saveGrant(t, st, &store.Grant{
		ID: "grant-" + clientID, Subject: "user", ClientID: clientID,
		CreatedAt: now, UpdatedAt: now,
	})
}

// TestCoordinator_NotifyDetachedReturnsWhileDeliveryIsInFlight pins the
// property the /end_session endpoint depends on: handing a fan-out to
// the coordinator costs the caller nothing, even when the relying
// party never answers. The deliverer here blocks indefinitely; if
// NotifyDetached waited on it the test would never reach the release.
//
// OpenID Connect Back-Channel Logout 1.0 makes delivery an exchange
// independent of the end-user's user agent and tolerates an RP missing
// a Logout Token entirely, so nothing about the logout response owes
// the browser a completed delivery.
func TestCoordinator_NotifyDetachedReturnsWhileDeliveryIsInFlight(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{})
	release := make(chan struct{})
	deliver := backchannel.DelivererFunc(func(context.Context, backchannel.Target, string) error {
		close(entered)
		<-release
		return nil
	})
	coord, st, rec := newCoordinatorFixture(t, deliver)
	seedTarget(t, st, "rp-a", "https://rp-a.example/logout")

	coord.NotifyDetached(context.Background(), backchannel.Notice{Subject: "user", SessionID: "sid-1"})

	// NotifyDetached has already returned. Wait for the delivery to be
	// under way, so the assertion below is made while the RP is still
	// holding the connection open.
	select {
	case <-entered:
	case <-time.After(drainTimeout):
		t.Fatal("delivery never started after NotifyDetached returned")
	}
	close(release)
	drain(t, coord)

	if ev := findEvent(rec.snapshot(), "logout.back_channel.delivered"); ev == nil {
		t.Fatalf("delivery outcome not audited: %#v", rec.snapshot())
	}
}

// fanOutWatcher forwards every record to the underlying recorder and
// republishes successful deliveries on a channel, so a test can wait
// for a specific relying party's outcome instead of polling.
type fanOutWatcher struct {
	*recordingEmitter
	delivered chan string
}

func (w *fanOutWatcher) Emit(ctx context.Context, ev audit.Event) {
	w.recordingEmitter.Emit(ctx, ev)
	if ev.Name == "logout.back_channel.delivered" {
		w.delivered <- ev.ClientID
	}
}

// TestCoordinator_SlowTargetDoesNotStallSiblings pins that the
// fan-out's per-RP isolation survived the move to a background
// goroutine: one relying party holding its connection open must not
// delay the logout tokens bound for the others. The healthy targets
// are asserted to have been delivered while the slow one is still
// wedged, which is only reachable if they were dispatched
// concurrently rather than behind it.
func TestCoordinator_SlowTargetDoesNotStallSiblings(t *testing.T) {
	t.Parallel()
	const slowClient = "rp-slow"
	entered := make(chan struct{})
	release := make(chan struct{})
	deliver := backchannel.DelivererFunc(func(_ context.Context, target backchannel.Target, _ string) error {
		if target.ClientID == slowClient {
			close(entered)
			<-release
		}
		return nil
	})
	_, signing := mustKey(t)
	st := inmem.New()
	watcher := &fanOutWatcher{recordingEmitter: &recordingEmitter{}, delivered: make(chan string, 3)}
	coord, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer:    "https://op.example.com",
		Signing:   signing,
		Clients:   st.Clients(),
		Grants:    st.Grants().(store.GrantClientLister),
		Deliverer: deliver,
		Emitter:   watcher,
		Clock:     fixedClock(time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	seedTarget(t, st, slowClient, "https://rp-slow.example/logout")
	seedTarget(t, st, "rp-fast-a", "https://rp-fast-a.example/logout")
	seedTarget(t, st, "rp-fast-b", "https://rp-fast-b.example/logout")

	coord.NotifyDetached(context.Background(), backchannel.Notice{Subject: "user", SessionID: "sid-1"})
	select {
	case <-entered:
	case <-time.After(drainTimeout):
		t.Fatal("the slow target's delivery never started")
	}

	// Still inside the wedged delivery: both healthy RPs must already
	// have their logout tokens.
	got := map[string]bool{}
	for range 2 {
		select {
		case clientID := <-watcher.delivered:
			got[clientID] = true
		case <-time.After(drainTimeout):
			t.Fatalf("healthy targets stalled behind %s; delivered=%v", slowClient, got)
		}
	}
	if got[slowClient] {
		t.Fatalf("the wedged target reported delivery: %v", got)
	}
	if !got["rp-fast-a"] || !got["rp-fast-b"] {
		t.Errorf("delivered=%v want both healthy targets", got)
	}

	close(release)
	drain(t, coord)
	if len(watcher.snapshot()) < 3 {
		t.Errorf("recorded %d events, want one per target", len(watcher.snapshot()))
	}
}

// TestCoordinator_DetachedDeliveryFailureIsAudited is the observability
// half of the detachment: the caller no longer sees a return value, so
// a failed delivery has to remain visible through the audit chain,
// which is also what feeds the back-channel logout metric.
func TestCoordinator_DetachedDeliveryFailureIsAudited(t *testing.T) {
	t.Parallel()
	boom := errors.New("rp refused the logout token")
	deliver := backchannel.DelivererFunc(func(context.Context, backchannel.Target, string) error {
		return boom
	})
	coord, st, rec := newCoordinatorFixture(t, deliver)
	seedTarget(t, st, "rp-a", "https://rp-a.example/logout")

	coord.NotifyDetached(context.Background(), backchannel.Notice{Subject: "user", SessionID: "sid-1"})
	drain(t, coord)

	ev := findEvent(rec.snapshot(), "logout.back_channel.failed")
	if ev == nil {
		t.Fatalf("detached delivery failure not audited: %#v", rec.snapshot())
	}
	if ev.ClientID != "rp-a" {
		t.Errorf("failure event client_id=%q want rp-a", ev.ClientID)
	}
	if got, _ := ev.Extras["error"].(string); !strings.Contains(got, boom.Error()) {
		t.Errorf("failure event error=%q does not carry the delivery cause", got)
	}
}

// TestCoordinator_DetachedFanOutIsBoundedByBudget pins the bound that
// replaces the request's lifetime. The deliverer waits for its context
// and nothing else, so an unbounded fan-out would never finish; the
// per-fan-out budget is what ends it. The budget is deliberately set
// below any scheduling granularity rather than being slept through, so
// the test asserts an outcome instead of a duration, and the stores
// are wrapped to ignore it so the assertion lands on the delivery step
// rather than on whichever lookup noticed the deadline first.
func TestCoordinator_DetachedFanOutIsBoundedByBudget(t *testing.T) {
	t.Parallel()
	deliver := backchannel.DelivererFunc(func(ctx context.Context, _ backchannel.Target, _ string) error {
		<-ctx.Done()
		return ctx.Err()
	})
	_, signing := mustKey(t)
	st := inmem.New()
	rec := &recordingEmitter{}
	coord, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer:       "https://op.example.com",
		Signing:      signing,
		Clients:      deadlineBlindClients{ClientStore: st.Clients()},
		Grants:       deadlineBlindLister{GrantClientLister: st.Grants().(store.GrantClientLister)},
		Deliverer:    deliver,
		Emitter:      rec,
		Clock:        fixedClock(time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)),
		FanOutBudget: time.Nanosecond,
	})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	seedTarget(t, st, "rp-a", "https://rp-a.example/logout")

	coord.NotifyDetached(context.Background(), backchannel.Notice{Subject: "user", SessionID: "sid-1"})
	drain(t, coord)

	ev := findEvent(rec.snapshot(), "logout.back_channel.failed")
	if ev == nil {
		t.Fatalf("abandoned delivery not audited: %#v", rec.snapshot())
	}
	if got, _ := ev.Extras["error"].(string); !strings.Contains(got, context.DeadlineExceeded.Error()) {
		t.Errorf("failure event error=%q does not name the elapsed budget", got)
	}
}

// TestCoordinator_DetachedFanOutSurvivesRequestCancellation covers the
// other side of the same seam: the fan-out is derived from the request
// context for its values, but detaching it from the request's
// cancellation is the whole point. A user agent that disconnects the
// moment the logout response lands must not cancel the deliveries that
// are still on their way to the relying parties.
func TestCoordinator_DetachedFanOutSurvivesRequestCancellation(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{})
	proceed := make(chan struct{})
	deliverErr := make(chan error, 1)
	deliver := backchannel.DelivererFunc(func(ctx context.Context, _ backchannel.Target, _ string) error {
		close(entered)
		<-proceed
		deliverErr <- ctx.Err()
		return nil
	})
	coord, st, rec := newCoordinatorFixture(t, deliver)
	seedTarget(t, st, "rp-a", "https://rp-a.example/logout")

	requestCtx, cancelRequest := context.WithCancel(context.Background())
	coord.NotifyDetached(requestCtx, backchannel.Notice{Subject: "user", SessionID: "sid-1"})
	select {
	case <-entered:
	case <-time.After(drainTimeout):
		t.Fatal("delivery never started after NotifyDetached returned")
	}
	cancelRequest()
	close(proceed)
	drain(t, coord)

	if err := <-deliverErr; err != nil {
		t.Errorf("delivery context ended with %v; request cancellation reached the detached fan-out", err)
	}
	if ev := findEvent(rec.snapshot(), "logout.back_channel.delivered"); ev == nil {
		t.Fatalf("delivery did not complete after the request was cancelled: %#v", rec.snapshot())
	}
}

// TestCoordinator_ShedsFanOutOverInflightCap pins the back-pressure
// that detaching removed. Without a cap, an adversary registering
// black-holing backchannel_logout_uri values could turn a burst of
// logouts into an unbounded pile of long-lived outbound connections.
// Over the cap the fan-out is refused, and the refusal is audited so
// the RPs that went unnotified are not lost silently.
func TestCoordinator_ShedsFanOutOverInflightCap(t *testing.T) {
	t.Parallel()
	entered := make(chan struct{})
	release := make(chan struct{})
	deliver := backchannel.DelivererFunc(func(context.Context, backchannel.Target, string) error {
		close(entered)
		<-release
		return nil
	})
	_, signing := mustKey(t)
	st := inmem.New()
	rec := &recordingEmitter{}
	coord, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer:             "https://op.example.com",
		Signing:            signing,
		Clients:            st.Clients(),
		Grants:             st.Grants().(store.GrantClientLister),
		Deliverer:          deliver,
		Emitter:            rec,
		Clock:              fixedClock(time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)),
		MaxInflightFanOuts: 1,
	})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	seedTarget(t, st, "rp-a", "https://rp-a.example/logout")

	coord.NotifyDetached(context.Background(), backchannel.Notice{Subject: "user", SessionID: "sid-1"})
	select {
	case <-entered:
	case <-time.After(drainTimeout):
		t.Fatal("first fan-out never started")
	}
	// The only slot is occupied by the wedged fan-out above.
	coord.NotifyDetached(context.Background(), backchannel.Notice{Subject: "user", SessionID: "sid-2"})

	var shed *audit.Event
	for _, ev := range rec.snapshot() {
		if ev.Name == "logout.back_channel.failed" && ev.Extras["failure_stage"] == "fanout_capacity" {
			shed = &ev
			break
		}
	}
	if shed == nil {
		t.Fatalf("shed fan-out not audited: %#v", rec.snapshot())
	}
	if shed.SessionID != "sid-2" {
		t.Errorf("shed event session_id=%q want sid-2", shed.SessionID)
	}
	close(release)
	drain(t, coord)
}

// TestCoordinator_DetachedResolutionFailureIsAudited covers the error
// the synchronous entry point used to return to the /end_session
// handler, which audited it. Detaching removed that return path, so
// the coordinator now emits the same record itself; losing it would
// leave a store outage invisible.
func TestCoordinator_DetachedResolutionFailureIsAudited(t *testing.T) {
	t.Parallel()
	boom := errors.New("grant backend unavailable")
	deliver := backchannel.DelivererFunc(func(context.Context, backchannel.Target, string) error {
		t.Error("deliverer called despite an unreadable audience page")
		return nil
	})
	_, signing := mustKey(t)
	st := inmem.New()
	rec := &recordingEmitter{}
	coord, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer:    "https://op.example.com",
		Signing:   signing,
		Clients:   st.Clients(),
		Grants:    faultingAudienceStore{GrantClientLister: st.Grants().(store.GrantClientLister), err: boom},
		Deliverer: deliver,
		Emitter:   rec,
		Clock:     fixedClock(time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}

	coord.NotifyDetached(context.Background(), backchannel.Notice{Subject: "user", SessionID: "sid-1"})
	drain(t, coord)

	ev := findEvent(rec.snapshot(), "logout.back_channel.resolve_failed")
	if ev == nil {
		t.Fatalf("detached resolution failure not audited: %#v", rec.snapshot())
	}
	if got, _ := ev.Extras["error"].(string); !strings.Contains(got, boom.Error()) {
		t.Errorf("resolve_failed error=%q does not carry the store fault", got)
	}
}

// TestCoordinator_DetachedDeliveryKeepsSSRFDenyList pins that moving
// the fan-out off the request path did not move it around the
// deliverer's guard. The default [backchannel.HTTPDeliverer] still
// refuses a target that resolves into a deny-listed network, and the
// refusal is reported as a delivery failure like any other. The target
// is an IP literal so the check needs no DNS round-trip.
func TestCoordinator_DetachedDeliveryKeepsSSRFDenyList(t *testing.T) {
	t.Parallel()
	_, signing := mustKey(t)
	st := inmem.New()
	rec := &recordingEmitter{}
	coord, err := backchannel.NewCoordinator(backchannel.Config{
		Issuer:  "https://op.example.com",
		Signing: signing,
		Clients: st.Clients(),
		Grants:  st.Grants().(store.GrantClientLister),
		Emitter: rec,
		Clock:   fixedClock(time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)),
	})
	if err != nil {
		t.Fatalf("NewCoordinator: %v", err)
	}
	seedTarget(t, st, "rp-loopback", "http://127.0.0.1:1/logout")

	coord.NotifyDetached(context.Background(), backchannel.Notice{Subject: "user", SessionID: "sid-1"})
	drain(t, coord)

	ev := findEvent(rec.snapshot(), "logout.back_channel.failed")
	if ev == nil {
		t.Fatalf("deny-listed target did not produce a failure record: %#v", rec.snapshot())
	}
	if got, _ := ev.Extras["error"].(string); !strings.Contains(got, backchannel.ErrPrivateNetworkBlocked.Error()) {
		t.Errorf("failure event error=%q does not name the deny-list refusal", got)
	}
	if findEvent(rec.snapshot(), "logout.back_channel.delivered") != nil {
		t.Error("deny-listed target was reported as delivered")
	}
}

// deadlineBlindLister / deadlineBlindClients strip cancellation from
// the context the coordinator passes to the target-resolution
// lookups. They let a test hand the fan-out an already-elapsed budget
// and still reach the delivery step, which is the step under
// assertion.
type deadlineBlindLister struct {
	store.GrantClientLister
}

func (s deadlineBlindLister) ListClientIDsBySubject(
	ctx context.Context,
	subject, cursor string,
	limit int,
) (store.GrantClientPage, error) {
	return s.GrantClientLister.ListClientIDsBySubject(
		context.WithoutCancel(ctx), subject, cursor, limit,
	)
}

type deadlineBlindClients struct {
	store.ClientStore
}

func (s deadlineBlindClients) GetClient(ctx context.Context, id string) (*store.Client, error) {
	return s.ClientStore.GetClient(context.WithoutCancel(ctx), id)
}

// faultingAudienceStore fails the audience-page query the coordinator
// issues first, so the fan-out cannot resolve any target.
type faultingAudienceStore struct {
	store.GrantClientLister
	err error
}

func (s faultingAudienceStore) ListClientIDsBySubject(
	context.Context,
	string, string,
	int,
) (store.GrantClientPage, error) {
	return store.GrantClientPage{}, s.err
}
