package inmem

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

func assertSSFStreamIndex(t *testing.T, st *ssfState) {
	t.Helper()
	st.mu.Lock()
	defer st.mu.Unlock()
	want := make(map[string][]string)
	for jti, ev := range st.events {
		want[ev.StreamID] = append(want[ev.StreamID], jti)
	}
	if len(want) != len(st.byStream) {
		t.Fatalf("byStream has %d streams, events span %d", len(st.byStream), len(want))
	}
	for stream, jtis := range want {
		got := make([]string, 0, len(st.byStream[stream]))
		for jti := range st.byStream[stream] {
			got = append(got, jti)
		}
		slices.Sort(got)
		slices.Sort(jtis)
		if !slices.Equal(got, jtis) {
			t.Fatalf("stream %s index = %v, events = %v", stream, got, jtis)
		}
	}
}

func TestSSFClaimDueOrderingAndLimits(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := New()
	events := s.SSFEvents()
	base := time.Unix(1_700_000_000, 0)
	enqueue := func(jti, stream string, offset time.Duration, delivery store.SSFDeliveryMethod) {
		t.Helper()
		if err := events.Enqueue(ctx, &store.SSFEvent{
			JTI: jti, StreamID: stream, Kind: store.SSFEventKindEvent, Delivery: delivery,
			Claims: []byte(`{}`), NextAttemptAt: base.Add(offset), ExpiresAt: base.Add(time.Hour),
		}); err != nil {
			t.Fatalf("Enqueue %s: %v", jti, err)
		}
	}
	enqueue("a1", "A", 1*time.Second, store.SSFDeliveryPush)
	enqueue("a2", "A", 2*time.Second, store.SSFDeliveryPush)
	enqueue("a3", "A", 3*time.Second, store.SSFDeliveryPush)
	enqueue("b1", "B", 4*time.Second, store.SSFDeliveryPush)
	enqueue("b2", "B", 5*time.Second, store.SSFDeliveryPush)
	enqueue("c1", "C", 6*time.Second, store.SSFDeliveryPush)
	enqueue("poll", "C", 0, store.SSFDeliveryPoll)
	enqueue("future", "C", time.Hour, store.SSFDeliveryPush)

	got, err := events.ClaimDue(ctx, base.Add(10*time.Second), 4, 2, time.Minute)
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	var jtis []string
	for _, ev := range got {
		jtis = append(jtis, ev.JTI)
	}
	// Stream A is capped at two, so a3 is skipped; n=4 cuts the list after b2.
	if want := []string{"a1", "a2", "b1", "b2"}; !slices.Equal(jtis, want) {
		t.Fatalf("ClaimDue = %v, want %v", jtis, want)
	}
	again, err := events.ClaimDue(ctx, base.Add(10*time.Second), 10, 2, time.Minute)
	if err != nil {
		t.Fatalf("ClaimDue again: %v", err)
	}
	jtis = jtis[:0]
	for _, ev := range again {
		jtis = append(jtis, ev.JTI)
	}
	// Leased events are not due again; a3 and c1 remain.
	if want := []string{"a3", "c1"}; !slices.Equal(jtis, want) {
		t.Fatalf("second ClaimDue = %v, want %v", jtis, want)
	}
	assertSSFStreamIndex(t, s.ssfEvents.st)
}

func TestSSFStreamIndexFollowsEventLifecycle(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := New()
	base := time.Unix(1_700_000_000, 0)
	for _, id := range []string{"s1", "s2"} {
		if err := s.SSFStreams().Create(ctx, &store.SSFStream{
			ID: id, ClientID: "client-" + id, Status: store.SSFStreamEnabled,
			Delivery: store.SSFDelivery{Method: store.SSFDeliveryPoll},
		}); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
	}
	for _, ev := range []struct{ jti, stream string }{{"e1", "s1"}, {"e2", "s1"}, {"e3", "s2"}} {
		if err := s.SSFEvents().Enqueue(ctx, &store.SSFEvent{
			JTI: ev.jti, StreamID: ev.stream, Kind: store.SSFEventKindEvent, Delivery: store.SSFDeliveryPoll,
			Claims: []byte(`{}`), NextAttemptAt: base, ExpiresAt: base.Add(time.Hour),
		}); err != nil {
			t.Fatalf("Enqueue %s: %v", ev.jti, err)
		}
	}
	assertSSFStreamIndex(t, s.ssfEvents.st)

	if err := s.SSFEvents().Ack(ctx, "s1", []string{"e1"}); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	assertSSFStreamIndex(t, s.ssfEvents.st)

	pending, _, err := s.SSFEvents().Pending(ctx, "s1", 10)
	if err != nil || len(pending) != 1 || pending[0].JTI != "e2" {
		t.Fatalf("Pending(s1) = %v, %v; want [e2]", pending, err)
	}

	if n, err := s.SSFEvents().DeleteExpired(ctx, base.Add(2*time.Hour)); err != nil || n != 2 {
		t.Fatalf("DeleteExpired = %d, %v; want 2, nil", n, err)
	}
	assertSSFStreamIndex(t, s.ssfEvents.st)

	if err := s.SSFEvents().Enqueue(ctx, &store.SSFEvent{
		JTI: "e4", StreamID: "s2", Kind: store.SSFEventKindEvent, Delivery: store.SSFDeliveryPoll,
		Claims: []byte(`{}`), NextAttemptAt: base, ExpiresAt: base.Add(time.Hour),
	}); err != nil {
		t.Fatalf("Enqueue e4: %v", err)
	}
	if err := s.SSFStreams().Delete(ctx, "s2"); err != nil {
		t.Fatalf("Delete stream: %v", err)
	}
	assertSSFStreamIndex(t, s.ssfEvents.st)
	if len(s.ssfEvents.st.events) != 0 {
		t.Fatalf("stream delete left events behind: %v", s.ssfEvents.st.events)
	}
}
