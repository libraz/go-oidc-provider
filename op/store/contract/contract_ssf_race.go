package contract

import (
	"context"
	"errors"
	"fmt"
	"testing"

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
