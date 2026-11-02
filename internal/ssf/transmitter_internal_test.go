package ssf

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

var errInjected = errors.New("injected backend fault")

type faultGrants struct {
	store.GrantClientLister
	err error
}

func (g *faultGrants) ListClientIDsBySubject(ctx context.Context, subject, cursor string, limit int) (store.GrantClientPage, error) {
	if g.err != nil {
		return store.GrantClientPage{}, g.err
	}
	return g.GrantClientLister.ListClientIDsBySubject(ctx, subject, cursor, limit)
}

type countingStreams struct {
	store.SSFStreamStore
	listCalls atomic.Int32
	err       error
}

func (s *countingStreams) ListActive(ctx context.Context) ([]*store.SSFStream, error) {
	s.listCalls.Add(1)
	if s.err != nil {
		return nil, s.err
	}
	return s.SSFStreamStore.ListActive(ctx)
}

type faultEvents struct {
	store.SSFEventStore
	failStream string
}

func (e *faultEvents) Enqueue(ctx context.Context, ev *store.SSFEvent) error {
	if ev.StreamID == e.failStream {
		return errInjected
	}
	return e.SSFEventStore.Enqueue(ctx, ev)
}

func requireReason(t *testing.T, rec *recordingAudit, reason string) audit.Event {
	t.Helper()
	for _, ev := range rec.named(eventEnqueueFailed) {
		if ev.Extras["reason"] == reason {
			return ev
		}
	}
	t.Fatalf("no %s event with reason %q", eventEnqueueFailed, reason)
	return audit.Event{}
}

func TestTransmitter_PublishFansOutToGrantHoldersWithMatchingStreams(t *testing.T) {
	t.Parallel()
	st := newTestStores(t)
	rec := &recordingAudit{}
	tr := newTestTransmitter(t, testDeps(t, st, rec))

	seedReceiver(t, st, "rp-a", "alice")
	a := seedStream(t, st, "rp-a", store.SSFStreamEnabled, store.SSFDeliveryPoll, EventSessionRevoked)
	seedReceiver(t, st, "rp-b", "alice")
	b := seedStream(t, st, "rp-b", store.SSFStreamEnabled, store.SSFDeliveryPoll, EventSessionRevoked, EventCredentialChange)
	// Grant but no stream.
	seedReceiver(t, st, "rp-nostream", "alice")
	// Stream but no grant for alice.
	seedReceiver(t, st, "rp-other", "bob")
	other := seedStream(t, st, "rp-other", store.SSFStreamEnabled, store.SSFDeliveryPoll, EventSessionRevoked)
	// Stream not delivering the event.
	seedReceiver(t, st, "rp-unsub", "alice")
	unsub := seedStream(t, st, "rp-unsub", store.SSFStreamEnabled, store.SSFDeliveryPoll, EventCredentialChange)

	n, err := tr.Publish(context.Background(), EventSessionRevoked, "alice", Fields{InitiatingEntity: InitiatingEntityUser})
	if err != nil || n != 2 {
		t.Fatalf("Publish = %d, %v; want 2, nil", n, err)
	}
	if got := len(pendingEvents(t, st, other.ID)) + len(pendingEvents(t, st, unsub.ID)); got != 0 {
		t.Errorf("%d SETs reached streams without a grant or subscription", got)
	}

	txns := make([]any, 0, 2)
	jtis := map[string]bool{}
	for _, s := range []*store.SSFStream{a, b} {
		evs := pendingEvents(t, st, s.ID)
		if len(evs) != 1 {
			t.Fatalf("stream %s: %d events, want 1", s.ID, len(evs))
		}
		ev := evs[0]
		if ev.Kind != store.SSFEventKindEvent || ev.Held || ev.Delivery != store.SSFDeliveryPoll {
			t.Errorf("event row = %+v", ev)
		}
		if !ev.NextAttemptAt.Equal(testNow) || !ev.ExpiresAt.Equal(testNow.Add(eventTTL)) {
			t.Errorf("times = %v / %v", ev.NextAttemptAt, ev.ExpiresAt)
		}
		c := decodeClaims(t, ev.Claims)
		if c["aud"] != s.ClientID || c["iss"] != testIssuer || c["jti"] != ev.JTI {
			t.Errorf("claims = %v", c)
		}
		if _, ok := c["sub"]; ok {
			t.Error("claims carry sub")
		}
		subID := c["sub_id"].(map[string]any)
		if subID["format"] != "iss_sub" || subID["sub"] != "alice" {
			t.Errorf("sub_id = %v", subID)
		}
		key, payload := eventMember(t, c)
		if key != string(EventSessionRevoked) || payload["initiating_entity"] != "user" || payload["reason_admin"] == nil {
			t.Errorf("event %s = %v", key, payload)
		}
		txns = append(txns, c["txn"])
		jtis[ev.JTI] = true
	}
	if txns[0] == nil || txns[0] != txns[1] {
		t.Errorf("txn = %v, want one shared non-empty value", txns)
	}
	if len(jtis) != 2 {
		t.Error("jti reused across receivers")
	}
	if got := len(rec.named(eventEnqueued)); got != 2 {
		t.Errorf("%s events = %d, want 2", eventEnqueued, got)
	}
}

func TestTransmitter_PublishProjectsSubjectPerClient(t *testing.T) {
	t.Parallel()
	st := newTestStores(t)
	d := testDeps(t, st, &recordingAudit{})
	d.SubjectProjector = func(_ context.Context, raw string, c *store.Client) (string, error) {
		return "pairwise-" + c.ID + "-" + raw, nil
	}
	tr := newTestTransmitter(t, d)
	ids := []string{"rp-a", "rp-b"}
	streams := make([]*store.SSFStream, 0, len(ids))
	for _, id := range ids {
		seedReceiver(t, st, id, "alice")
		streams = append(streams, seedStream(t, st, id, store.SSFStreamEnabled, store.SSFDeliveryPoll, EventSessionRevoked))
	}
	if _, err := tr.Publish(context.Background(), EventSessionRevoked, "alice", Fields{}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	subs := map[any]bool{}
	for _, s := range streams {
		c := decodeClaims(t, pendingEvents(t, st, s.ID)[0].Claims)
		sub := c["sub_id"].(map[string]any)["sub"]
		if sub != "pairwise-"+s.ClientID+"-alice" {
			t.Errorf("%s: sub_id.sub = %v", s.ClientID, sub)
		}
		subs[sub] = true
	}
	if len(subs) != 2 {
		t.Error("two pairwise receivers saw the same subject")
	}
}

func TestTransmitter_PausedHoldsDisabledSkips(t *testing.T) {
	t.Parallel()
	st := newTestStores(t)
	rec := &recordingAudit{}
	tr := newTestTransmitter(t, testDeps(t, st, rec))
	seedReceiver(t, st, "rp-paused", "alice")
	paused := seedStream(t, st, "rp-paused", store.SSFStreamPaused, store.SSFDeliveryPoll, EventSessionRevoked)
	seedReceiver(t, st, "rp-disabled", "alice")
	disabled := seedStream(t, st, "rp-disabled", store.SSFStreamDisabled, store.SSFDeliveryPoll, EventSessionRevoked)

	n, err := tr.Publish(context.Background(), EventSessionRevoked, "alice", Fields{})
	if err != nil || n != 1 {
		t.Fatalf("Publish = %d, %v; want 1, nil", n, err)
	}
	if got := pendingEvents(t, st, paused.ID); len(got) != 0 {
		t.Errorf("paused stream exposed %d unheld events", len(got))
	}
	enq := rec.named(eventEnqueued)
	if len(enq) != 1 || enq[0].Extras["held"] != true || enq[0].Extras["stream_id"] != paused.ID {
		t.Fatalf("enqueued audit = %+v", enq)
	}
	paused.Status = store.SSFStreamEnabled
	if err := tr.UpdateStream(context.Background(), paused, nil); err != nil {
		t.Fatalf("UpdateStream: %v", err)
	}
	if got := pendingEvents(t, st, paused.ID); len(got) != 1 {
		t.Errorf("after resume: %d events, want the held one", len(got))
	}
	if got := pendingEvents(t, st, disabled.ID); len(got) != 0 {
		t.Errorf("disabled stream received %d events", len(got))
	}
}

func TestTransmitter_PushStreamEventIsClaimable(t *testing.T) {
	t.Parallel()
	st := newTestStores(t)
	tr := newTestTransmitter(t, testDeps(t, st, &recordingAudit{}))
	seedReceiver(t, st, "rp-push", "alice")
	s := seedStream(t, st, "rp-push", store.SSFStreamEnabled, store.SSFDeliveryPush, EventAccountDisabled)

	if _, err := tr.Publish(context.Background(), EventAccountDisabled, "alice", Fields{Reason: "hijacking"}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	evs, err := st.SSFEvents().ClaimDue(context.Background(), testNow, 10, 10, time.Minute)
	if err != nil || len(evs) != 1 {
		t.Fatalf("ClaimDue = %d, %v", len(evs), err)
	}
	if evs[0].StreamID != s.ID || evs[0].Delivery != store.SSFDeliveryPush {
		t.Errorf("claimed = %+v", evs[0])
	}
	key, payload := eventMember(t, decodeClaims(t, evs[0].Claims))
	if key != string(EventAccountDisabled) || payload["reason"] != "hijacking" {
		t.Errorf("event %s = %v", key, payload)
	}
	// A queued claim set signs verbatim at delivery time.
	k, pub := testKey(t, "sig-delivery")
	compact, err := Sign(evs[0].Claims, k)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if hdr, _ := verifySET(t, compact, pub); hdr.KeyID != "sig-delivery" {
		t.Errorf("kid = %q", hdr.KeyID)
	}
}

func TestTransmitter_FanoutCapacity(t *testing.T) {
	t.Parallel()
	st := newTestStores(t)
	rec := &recordingAudit{}
	tr := newTestTransmitter(t, testDeps(t, st, rec))
	for i := range maxFanOut + 1 {
		id := fmt.Sprintf("rp-%03d", i)
		seedReceiver(t, st, id, "alice")
		seedStream(t, st, id, store.SSFStreamEnabled, store.SSFDeliveryPoll, EventSessionRevoked)
	}
	n, err := tr.Publish(context.Background(), EventSessionRevoked, "alice", Fields{})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if n != maxFanOut {
		t.Errorf("enqueued %d, want the cap %d", n, maxFanOut)
	}
	requireReason(t, rec, reasonFanoutCapacity)
}

func TestTransmitter_NoGrantSkipsStreamRead(t *testing.T) {
	t.Parallel()
	st := newTestStores(t)
	d := testDeps(t, st, &recordingAudit{})
	streams := &countingStreams{SSFStreamStore: st.SSFStreams()}
	d.Streams = streams
	tr := newTestTransmitter(t, d)
	if n, err := tr.Publish(context.Background(), EventSessionRevoked, "nobody", Fields{}); n != 0 || err != nil {
		t.Fatalf("Publish = %d, %v", n, err)
	}
	if got := streams.listCalls.Load(); got != 0 {
		t.Errorf("ListActive called %d times for a subject without grants", got)
	}
}

func TestTransmitter_ReadsActiveStreamsOnce(t *testing.T) {
	t.Parallel()
	st := newTestStores(t)
	d := testDeps(t, st, &recordingAudit{})
	streams := &countingStreams{SSFStreamStore: st.SSFStreams()}
	d.Streams = streams
	tr := newTestTransmitter(t, d)
	for _, id := range []string{"rp-a", "rp-b", "rp-c"} {
		seedReceiver(t, st, id, "alice")
		seedStream(t, st, id, store.SSFStreamEnabled, store.SSFDeliveryPoll, EventSessionRevoked)
	}
	if _, err := tr.Publish(context.Background(), EventSessionRevoked, "alice", Fields{}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if got := streams.listCalls.Load(); got != 1 {
		t.Errorf("ListActive called %d times, want 1", got)
	}
}

func TestTransmitter_MissingClientIsSkipped(t *testing.T) {
	t.Parallel()
	st := newTestStores(t)
	rec := &recordingAudit{}
	tr := newTestTransmitter(t, testDeps(t, st, rec))
	seedGrant(t, st, "rp-gone", "alice")
	seedStream(t, st, "rp-gone", store.SSFStreamEnabled, store.SSFDeliveryPoll, EventSessionRevoked)
	if n, err := tr.Publish(context.Background(), EventSessionRevoked, "alice", Fields{}); n != 0 || err != nil {
		t.Fatalf("Publish = %d, %v", n, err)
	}
	if got := rec.named(eventEnqueueFailed); len(got) != 0 {
		t.Errorf("stale grant audited as a failure: %+v", got)
	}
}

func TestTransmitter_PerReceiverFailureIsIsolated(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		reason string
		setup  func(d *Deps, failStream string)
	}{
		"projection": {
			reason: reasonProjection,
			setup: func(d *Deps, _ string) {
				d.SubjectProjector = func(_ context.Context, raw string, c *store.Client) (string, error) {
					if c.ID == "rp-bad" {
						return "", errInjected
					}
					return raw, nil
				}
			},
		},
		"empty projection": {
			reason: reasonProjection,
			setup: func(d *Deps, _ string) {
				d.SubjectProjector = func(_ context.Context, raw string, c *store.Client) (string, error) {
					if c.ID == "rp-bad" {
						return "", nil
					}
					return raw, nil
				}
			},
		},
		"enqueue": {
			reason: reasonEnqueue,
			setup: func(d *Deps, failStream string) {
				d.Events = &faultEvents{SSFEventStore: d.Events, failStream: failStream}
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			st := newTestStores(t)
			rec := &recordingAudit{}
			seedReceiver(t, st, "rp-bad", "alice")
			bad := seedStream(t, st, "rp-bad", store.SSFStreamEnabled, store.SSFDeliveryPoll, EventSessionRevoked)
			seedReceiver(t, st, "rp-good", "alice")
			good := seedStream(t, st, "rp-good", store.SSFStreamEnabled, store.SSFDeliveryPoll, EventSessionRevoked)
			d := testDeps(t, st, rec)
			tc.setup(&d, bad.ID)
			tr := newTestTransmitter(t, d)

			n, err := tr.Publish(context.Background(), EventSessionRevoked, "alice", Fields{})
			if err == nil || n != 1 {
				t.Fatalf("Publish = %d, %v; want 1 and an error", n, err)
			}
			if got := len(pendingEvents(t, st, good.ID)); got != 1 {
				t.Errorf("healthy receiver got %d events", got)
			}
			ev := requireReason(t, rec, tc.reason)
			if ev.ClientID != "rp-bad" || ev.Extras["stream_id"] != bad.ID {
				t.Errorf("failure audit = %+v", ev)
			}
		})
	}
}

func TestTransmitter_StoreReadFailures(t *testing.T) {
	t.Parallel()
	t.Run("grant lookup", func(t *testing.T) {
		t.Parallel()
		st := newTestStores(t)
		rec := &recordingAudit{}
		d := testDeps(t, st, rec)
		d.Grants = &faultGrants{GrantClientLister: d.Grants, err: errInjected}
		tr := newTestTransmitter(t, d)
		if _, err := tr.Publish(context.Background(), EventSessionRevoked, "alice", Fields{}); !errors.Is(err, errInjected) {
			t.Fatalf("err = %v", err)
		}
		requireReason(t, rec, reasonGrantLookup)
	})
	t.Run("stream list", func(t *testing.T) {
		t.Parallel()
		st := newTestStores(t)
		rec := &recordingAudit{}
		seedReceiver(t, st, "rp-a", "alice")
		d := testDeps(t, st, rec)
		d.Streams = &countingStreams{SSFStreamStore: d.Streams, err: errInjected}
		tr := newTestTransmitter(t, d)
		if _, err := tr.Publish(context.Background(), EventSessionRevoked, "alice", Fields{}); !errors.Is(err, errInjected) {
			t.Fatalf("err = %v", err)
		}
		requireReason(t, rec, reasonStreamList)
	})
}

func TestTransmitter_PublishRejectsInvalidInput(t *testing.T) {
	t.Parallel()
	st := newTestStores(t)
	tr := newTestTransmitter(t, testDeps(t, st, &recordingAudit{}))
	cases := map[string]struct {
		et      EventType
		subject string
		f       Fields
	}{
		"empty subject":       {et: EventSessionRevoked},
		"control event":       {et: EventVerification, subject: "alice"},
		"unknown event":       {et: "urn:example:unknown", subject: "alice"},
		"missing change_type": {et: EventCredentialChange, subject: "alice", f: Fields{CredentialType: "password"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := tr.Publish(context.Background(), tc.et, tc.subject, tc.f); !errors.Is(err, ErrInvalidEvent) {
				t.Fatalf("err = %v, want ErrInvalidEvent", err)
			}
		})
	}
}

func TestTransmitter_UpdateStreamNoticeIgnoresStatus(t *testing.T) {
	t.Parallel()
	st := newTestStores(t)
	rec := &recordingAudit{}
	tr := newTestTransmitter(t, testDeps(t, st, rec))
	seedReceiver(t, st, "rp-a", "alice")
	s := seedStream(t, st, "rp-a", store.SSFStreamEnabled, store.SSFDeliveryPoll)

	s.Status = store.SSFStreamDisabled
	if err := tr.UpdateStream(context.Background(), s, &ControlFields{Status: store.SSFStreamDisabled, Reason: "operator"}); err != nil {
		t.Fatalf("UpdateStream: %v", err)
	}
	evs := pendingEvents(t, st, s.ID)
	if len(evs) != 1 {
		t.Fatalf("%d events, want 1", len(evs))
	}
	ev := evs[0]
	enq := rec.named(eventEnqueued)
	if len(enq) != 1 || enq[0].Extras["jti"] != ev.JTI {
		t.Errorf("enqueued audit = %+v, want the notice", enq)
	}
	if ev.Kind != store.SSFEventKindStreamUpdated || ev.Held {
		t.Errorf("row = %+v", ev)
	}
	c := decodeClaims(t, ev.Claims)
	if subID := c["sub_id"].(map[string]any); subID["format"] != "opaque" || subID["id"] != s.ID {
		t.Errorf("sub_id = %v", subID)
	}
	if _, ok := c["txn"]; ok {
		t.Error("control event carries txn")
	}
	if c["aud"] != "rp-a" {
		t.Errorf("aud = %v", c["aud"])
	}
	key, payload := eventMember(t, c)
	if key != string(EventStreamUpdated) || payload["status"] != "disabled" || payload["reason"] != "operator" {
		t.Errorf("event %s = %v", key, payload)
	}
}

func TestTransmitter_EnqueueControlVerificationReplacesPending(t *testing.T) {
	t.Parallel()
	st := newTestStores(t)
	tr := newTestTransmitter(t, testDeps(t, st, &recordingAudit{}))
	seedReceiver(t, st, "rp-a", "alice")
	s := seedStream(t, st, "rp-a", store.SSFStreamPaused, store.SSFDeliveryPoll)

	for _, state := range []string{"first", "second"} {
		if _, err := tr.EnqueueControl(context.Background(), s, EventVerification, ControlFields{State: state}); err != nil {
			t.Fatalf("EnqueueControl(%s): %v", state, err)
		}
	}
	evs := pendingEvents(t, st, s.ID)
	if len(evs) != 1 {
		t.Fatalf("%d verifications pending, want 1", len(evs))
	}
	if evs[0].Kind != store.SSFEventKindVerification || evs[0].Held {
		t.Errorf("row = %+v", evs[0])
	}
	if _, payload := eventMember(t, decodeClaims(t, evs[0].Claims)); payload["state"] != "second" {
		t.Errorf("state = %v, want the latest", payload["state"])
	}
}

func TestTransmitter_EnqueueControlRejectsOrdinaryEvent(t *testing.T) {
	t.Parallel()
	st := newTestStores(t)
	tr := newTestTransmitter(t, testDeps(t, st, &recordingAudit{}))
	s := &store.SSFStream{ID: "s", ClientID: "rp", Delivery: store.SSFDelivery{Method: store.SSFDeliveryPoll}}
	if _, err := tr.EnqueueControl(context.Background(), s, EventSessionRevoked, ControlFields{}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("err = %v", err)
	}
	if _, err := tr.EnqueueControl(context.Background(), s, EventStreamUpdated, ControlFields{Status: store.SSFStreamPaused}); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("stream-updated through EnqueueControl: err = %v, want ErrInvalidEvent", err)
	}
	if _, err := tr.EnqueueControl(context.Background(), nil, EventVerification, ControlFields{}); err == nil {
		t.Fatal("nil stream accepted")
	}
}

func TestTransmitter_NewRequiresDeps(t *testing.T) {
	t.Parallel()
	st := newTestStores(t)
	full := testDeps(t, st, nil)
	cases := map[string]func(*Deps){
		"issuer":  func(d *Deps) { d.Issuer = "" },
		"streams": func(d *Deps) { d.Streams = nil },
		"events":  func(d *Deps) { d.Events = nil },
		"grants":  func(d *Deps) { d.Grants = nil },
		"clients": func(d *Deps) { d.Clients = nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := full
			mutate(&d)
			if _, err := New(d); err == nil {
				t.Fatal("New accepted incomplete deps")
			}
		})
	}
	d := full
	d.Audit, d.Clock = nil, nil
	if _, err := New(d); err != nil {
		t.Fatalf("New with nil Audit/Clock: %v", err)
	}
}

// staleStreams answers ListActive with a snapshot taken before a status
// or delivery-method change, the view a Publish racing that change holds.
type staleStreams struct {
	store.SSFStreamStore
	snapshot []*store.SSFStream
}

func (s *staleStreams) ListActive(context.Context) ([]*store.SSFStream, error) {
	out := make([]*store.SSFStream, 0, len(s.snapshot))
	for _, v := range s.snapshot {
		c := *v
		out = append(out, &c)
	}
	return out, nil
}

// TestTransmitter_PublishRacingStateChange pins that a SET built from a
// stream read before its status or delivery method changed lands under
// the stream's current state: held when paused, dropped when disabled,
// and tagged for the method the stream now uses.
func TestTransmitter_PublishRacingStateChange(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		change func(t *testing.T, st *inmem.Store, s *store.SSFStream)
		want   int
		check  func(t *testing.T, st *inmem.Store, s *store.SSFStream)
	}{
		{
			name: "paused", want: 1,
			change: func(t *testing.T, st *inmem.Store, s *store.SSFStream) {
				s.Status = store.SSFStreamPaused
				mustUpdate(t, st, s)
			},
			check: func(t *testing.T, st *inmem.Store, s *store.SSFStream) {
				if got := pendingEvents(t, st, s.ID); len(got) != 0 {
					t.Errorf("paused stream exposed %d events", len(got))
				}
				s.Status = store.SSFStreamEnabled
				mustUpdate(t, st, s)
				if got := pendingEvents(t, st, s.ID); len(got) != 1 {
					t.Errorf("after resume: %d events, want the held one", len(got))
				}
			},
		},
		{
			name: "disabled", want: 0,
			change: func(t *testing.T, st *inmem.Store, s *store.SSFStream) {
				s.Status = store.SSFStreamDisabled
				mustUpdate(t, st, s)
			},
			check: func(t *testing.T, st *inmem.Store, s *store.SSFStream) {
				s.Status = store.SSFStreamEnabled
				mustUpdate(t, st, s)
				if got := pendingEvents(t, st, s.ID); len(got) != 0 {
					t.Errorf("disabled stream kept %d events", len(got))
				}
			},
		},
		{
			name: "moved to push", want: 1,
			change: func(t *testing.T, st *inmem.Store, s *store.SSFStream) {
				s.Delivery = store.SSFDelivery{Method: store.SSFDeliveryPush, EndpointURL: "https://rp.example.com/push"}
				mustUpdate(t, st, s)
			},
			check: func(t *testing.T, st *inmem.Store, _ *store.SSFStream) {
				evs, err := st.SSFEvents().ClaimDue(context.Background(), testNow, 10, 10, time.Minute)
				if err != nil || len(evs) != 1 {
					t.Errorf("ClaimDue = %d, %v; want the SET tagged push", len(evs), err)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			st := newTestStores(t)
			seedReceiver(t, st, "rp-a", "alice")
			s := seedStream(t, st, "rp-a", store.SSFStreamEnabled, store.SSFDeliveryPoll, EventSessionRevoked)
			snapshot := *s
			deps := testDeps(t, st, &recordingAudit{})
			deps.Streams = &staleStreams{SSFStreamStore: st.SSFStreams(), snapshot: []*store.SSFStream{&snapshot}}
			tr := newTestTransmitter(t, deps)
			tc.change(t, st, s)
			if n, err := tr.Publish(context.Background(), EventSessionRevoked, "alice", Fields{}); err != nil || n != tc.want {
				t.Fatalf("Publish = %d, %v; want %d, nil", n, err, tc.want)
			}
			if tc.check != nil {
				tc.check(t, st, s)
			}
		})
	}
}

func mustUpdate(t *testing.T, st *inmem.Store, s *store.SSFStream) {
	t.Helper()
	if err := st.SSFStreams().Update(context.Background(), s, nil); err != nil {
		t.Fatalf("Update: %v", err)
	}
}
