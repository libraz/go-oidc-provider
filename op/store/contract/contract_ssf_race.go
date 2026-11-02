package contract

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// ssfRaceCases are the SSF cases that race a stream write. Enqueue's
// races live with the queue cases in [ssfCases]; [allSSFCases] is the
// table [RunSSF] drives.
//
//nolint:gochecknoglobals // sub-test table; declared once so the Run* entry point and the coverage check can iterate.
var ssfRaceCases = []factorCase[SSFBackend]{
	{"StreamCreateRacingClientHasOneWinner", ssfStreamCreateRace},
	{"UpdateRacingNoticesKeepOne", ssfUpdateNoticeRace},
	{"UpdateRacingUpdatesLeaveQueueAtFinalState", ssfUpdateStateRace},
}

// ssfStateRaceBacklog is the number of ordinary events queued before
// racing Updates, enough that each Update's queue move spans many writes.
const ssfStateRaceBacklog = 24

// ssfStateRaceRounds is how many times ssfUpdateStateRace races the
// Updates that keep the ordinary events.
const ssfStateRaceRounds = 3

// ssfRaceState is one racer's target status and delivery method.
type ssfRaceState struct {
	status store.SSFStreamStatus
	method store.SSFDeliveryMethod
}

// allSSFCases is every case [RunSSF] runs.
func allSSFCases() []factorCase[SSFBackend] {
	out := make([]factorCase[SSFBackend], 0, len(ssfCases)+len(ssfRaceCases))
	out = append(out, ssfCases...)
	return append(out, ssfRaceCases...)
}

// ssfStreamCreateRace pins the one-stream-per-receiver rule under
// concurrent Create calls: a backend that checks the ClientID and then
// inserts lets several streams in.
func ssfStreamCreateRace(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	errs := race(
		func() { _, _ = b.Streams.GetByClient(ctx, "ssf-race-warmup") },
		everyRacer(func(i int) error {
			return b.Streams.Create(ctx, ssfStream(fmt.Sprintf("stream-%d", i), "client-1", store.SSFStreamEnabled))
		})...,
	)
	winner := assertOneWinner(t, "SSFStreams().Create", errs)
	for i, err := range errs {
		if err != nil && !errors.Is(err, store.ErrConflict) {
			t.Fatalf("losing Create %d: want ErrConflict, got %v", i, err)
		}
	}
	got, err := b.Streams.GetByClient(ctx, "client-1")
	if err != nil {
		t.Fatalf("GetByClient: %v", err)
	}
	if want := fmt.Sprintf("stream-%d", winner); got.ID != want {
		t.Fatalf("stream stored for the client = %q, want the winner %q", got.ID, want)
	}
	active, err := b.Streams.ListActive(ctx)
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("streams stored after %d racing Creates = %d, want exactly one", concurrentRacers, len(active))
	}
}

// ssfUpdateNoticeRace pins the one-stream-updated rule under concurrent
// Update calls: a backend that deletes the queued notice and inserts its
// own in a transaction that cannot see its peers' rows keeps several.
func ssfUpdateNoticeRace(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	s := ssfStream("stream-1", "client-1", store.SSFStreamEnabled)
	s.Delivery = store.SSFDelivery{Method: store.SSFDeliveryPoll}
	if err := b.Streams.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}
	errs := race(
		func() { _, _, _ = b.Events.Pending(ctx, "ssf-race-warmup", 1) },
		everyRacer(func(i int) error {
			notice := ssfEvent(fmt.Sprintf("updated-%d", i), s.ID, store.SSFEventKindStreamUpdated, store.SSFDeliveryPoll)
			return b.Streams.Update(ctx, s, notice)
		})...,
	)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("racing Update %d: %v", i, err)
		}
	}
	got, _, err := b.Events.Pending(ctx, s.ID, 100)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("stream-updated events queued after %d racing Updates = %v, want exactly one", concurrentRacers, ssfJTIs(got))
	}
}

// ssfUpdateStateRace pins the queue move of concurrent Updates of one
// stream: once they return, every queued event carries the tags the
// stream's stored state implies, whichever Update stored it, and an
// Update that disabled the stream at any point leaves no ordinary event.
// A backend whose queue move is not ordered with its stream write lets a
// superseded Update's move land after the final one's.
func ssfUpdateStateRace(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	s := ssfStream("stream-1", "client-1", store.SSFStreamEnabled)
	if err := b.Streams.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}
	ordinary := make([]string, 0, ssfStateRaceBacklog)
	for i := range ssfStateRaceBacklog {
		jti := fmt.Sprintf("event-%02d", i)
		ordinary = append(ordinary, jti)
		enqueueSSF(t, b, ssfEvent(jti, s.ID, store.SSFEventKindEvent, store.SSFDeliveryPush))
	}
	enqueueSSF(t, b, ssfEvent("verify-1", s.ID, store.SSFEventKindVerification, store.SSFDeliveryPush))

	kept := []ssfRaceState{
		{store.SSFStreamEnabled, store.SSFDeliveryPoll},
		{store.SSFStreamPaused, store.SSFDeliveryPush},
		{store.SSFStreamPaused, store.SSFDeliveryPoll},
		{store.SSFStreamEnabled, store.SSFDeliveryPush},
	}
	now := Reference
	for round := range ssfStateRaceRounds {
		ssfRaceUpdates(t, b, s, round, kept)
		assertQueueAtStreamState(t, b, s.ID, now, ordinary)
		now = now.Add(ssfLease)
	}

	dropping := append([]ssfRaceState{{store.SSFStreamDisabled, store.SSFDeliveryPush}}, kept...)
	ssfRaceUpdates(t, b, s, ssfStateRaceRounds, dropping)
	assertQueueAtStreamState(t, b, s.ID, now, nil)
	// Re-enabling shows the ordinary events were dropped, not held.
	if err := b.Streams.Update(ctx, s, nil); err != nil {
		t.Fatalf("Update enabled: %v", err)
	}
	assertQueueAtStreamState(t, b, s.ID, now.Add(ssfLease), nil)
}

// ssfRaceUpdates races one Update of s per racer, each to a state of
// states in turn and carrying its own stream-updated notice.
func ssfRaceUpdates(t *testing.T, b SSFBackend, s *store.SSFStream, round int, states []ssfRaceState) {
	t.Helper()
	ctx := context.Background()
	errs := race(
		func() { _, _, _ = b.Events.Pending(ctx, "ssf-race-warmup", 1) },
		everyRacer(func(i int) error {
			state := states[(i+round)%len(states)]
			next := *s
			next.Status = state.status
			next.Delivery.Method = state.method
			notice := ssfEvent(fmt.Sprintf("updated-%d-%d", round, i), s.ID, store.SSFEventKindStreamUpdated, state.method)
			return b.Streams.Update(ctx, &next, notice)
		})...,
	)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("round %d: racing Update %d: %v", round, i, err)
		}
	}
}

// assertQueueAtStreamState fails unless the stream's queue is visible
// exactly as its stored state implies: its verification, one
// stream-updated notice and, while enabled, the listed ordinary events,
// all through the stored delivery method and none through the other.
func assertQueueAtStreamState(t *testing.T, b SSFBackend, streamID string, now time.Time, ordinary []string) {
	t.Helper()
	ctx := context.Background()
	st, err := b.Streams.Get(ctx, streamID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	want := []string{"verify-1"}
	if st.Status == store.SSFStreamEnabled {
		want = append(want, ordinary...)
	}
	claimed, err := b.Events.ClaimDue(ctx, now, 100, 100, ssfLease)
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	pending, _, err := b.Events.Pending(ctx, streamID, 100)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	seen, idle := claimed, pending
	if st.Delivery.Method == store.SSFDeliveryPoll {
		seen, idle = pending, claimed
	}
	if len(idle) != 0 {
		t.Fatalf("stream stored %s/%s, yet the other delivery method sees %v",
			st.Status, st.Delivery.Method, ssfJTIs(idle))
	}
	var got []string
	notices := 0
	for _, jti := range ssfJTIs(seen) {
		if strings.HasPrefix(jti, "updated-") {
			notices++
			continue
		}
		got = append(got, jti)
	}
	slices.Sort(want)
	if notices != 1 || !slices.Equal(got, want) {
		t.Fatalf("stream stored %s/%s sees %v, want %v and one stream-updated notice",
			st.Status, st.Delivery.Method, ssfJTIs(seen), want)
	}
}
