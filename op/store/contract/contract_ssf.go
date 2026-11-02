package contract

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// SSFBackend bundles the two substores of a [store.SharedSignalsStore].
// They are separate from [Backend] because a partial-coverage backend can
// host them without the rest of the aggregate. Both MUST share storage:
// [store.SSFStreamStore.Delete] removes the stream's queued events.
type SSFBackend struct {
	// Streams is the stream configuration substore under test.
	Streams store.SSFStreamStore

	// Events is the SET queue under test.
	Events store.SSFEventStore
}

// SSFFactory builds a fresh standalone SSF backend for a single contract
// sub-test.
type SSFFactory func(t *testing.T) SSFBackend

// ssfLease is the lease every ClaimDue case requests.
const ssfLease = time.Minute

//nolint:gochecknoglobals // sub-test table; declared once so the Run* entry point and the coverage check can iterate.
var ssfCases = []factorCase[SSFBackend]{
	{"StreamMissing", ssfStreamMissing},
	{"StreamCreateGetRoundTrip", ssfStreamRoundTrip},
	{"StreamCreateRejectsSecondStreamForClient", ssfStreamConflict},
	{"StreamListActiveSkipsDisabled", ssfStreamListActive},
	{"StreamUpdateReplaces", ssfStreamUpdate},
	{"StreamUpdateKeepsClientID", ssfStreamUpdateKeepsClient},
	{"StreamDeleteDropsQueuedEvents", ssfStreamDelete},
	{"StreamDefensiveCopies", ssfStreamDefensiveCopies},
	{"EnqueueRejectsDuplicateJTI", ssfEnqueueDuplicate},
	{"EnqueueReplacesQueuedControlOfSameKind", ssfEnqueueControlReplaces},
	{"EnqueueRefusesEventNotMatchingStream", ssfEnqueueMatchesStream},
	{"EnqueueRacingVerificationsKeepOne", ssfEnqueueVerificationRace},
	{"EnqueueRacingUpdateLeavesNoStaleEvent", ssfEnqueueUpdateRace},
	{"ClaimDueSelectsDueUnheldPush", ssfClaimDueSelects},
	{"ClaimDueEarliestFirst", ssfClaimDueOrder},
	{"ClaimDueCapsEachStream", ssfClaimDueStreamCap},
	{"ClaimDueLeaseHidesEventUntilItEnds", ssfClaimDueLease},
	{"ClaimDueHasOneWinner", ssfClaimDueOneWinner},
	{"RescheduleMovesNextAttempt", ssfReschedule},
	{"AckIsScopedToStream", ssfAck},
	{"PendingReportsMore", ssfPending},
	{"UpdateHoldsOnlyOrdinaryEvents", ssfUpdateHeld},
	{"UpdateMovesDelivery", ssfUpdateDelivery},
	{"UpdateDisabledDropsOnlyOrdinaryEvents", ssfUpdateDisabled},
	{"UpdateReplacesQueuedStreamUpdated", ssfUpdateNotice},
	{"DeleteExpired", ssfDeleteExpired},
	{"EventDefensiveCopies", ssfEventDefensiveCopies},
}

// RunSSF exercises the stream and SET-queue guarantees of
// [store.SharedSignalsStore]: stream CRUD and the one-stream-per-receiver
// rule, the hold / move / drop rules a stream Update applies to its queue
// that keep control events flowing through paused and disabled streams,
// the stream-state check on Enqueue, control-event replacement, and the
// lease ClaimDue hands to exactly one of several OP replicas. Adapter
// authors call it from their black-box test suite.
func RunSSF(t *testing.T, f SSFFactory) {
	t.Helper()
	for _, tc := range allSSFCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.run(t, f(t))
		})
	}
}

func ssfStreamMissing(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	if _, err := b.Streams.Get(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get(missing) = %v, want ErrNotFound", err)
	}
	if _, err := b.Streams.GetByClient(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetByClient(missing) = %v, want ErrNotFound", err)
	}
	if err := b.Streams.Update(ctx, ssfStream("missing", "client-missing", store.SSFStreamEnabled), nil); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Update(missing) = %v, want ErrNotFound", err)
	}
	if err := b.Streams.Delete(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Delete(missing) = %v, want ErrNotFound", err)
	}
}

func ssfStreamRoundTrip(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	want := ssfStream("stream-1", "client-1", store.SSFStreamEnabled)
	if err := b.Streams.Create(ctx, want); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := b.Streams.Get(ctx, want.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertSSFStreamEqual(t, got, want)
	byClient, err := b.Streams.GetByClient(ctx, want.ClientID)
	if err != nil {
		t.Fatalf("GetByClient: %v", err)
	}
	assertSSFStreamEqual(t, byClient, want)
}

func ssfStreamConflict(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	first := ssfStream("stream-1", "client-1", store.SSFStreamEnabled)
	if err := b.Streams.Create(ctx, first); err != nil {
		t.Fatalf("Create first: %v", err)
	}
	if err := b.Streams.Create(ctx, ssfStream("stream-2", "client-1", store.SSFStreamEnabled)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Create second stream for the same client = %v, want ErrConflict", err)
	}
	if err := b.Streams.Create(ctx, ssfStream("stream-1", "client-2", store.SSFStreamEnabled)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("Create with a taken stream ID = %v, want ErrConflict", err)
	}
	if _, err := b.Streams.Get(ctx, "stream-2"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get(rejected stream) = %v, want ErrNotFound", err)
	}
	got, err := b.Streams.GetByClient(ctx, "client-1")
	if err != nil {
		t.Fatalf("GetByClient: %v", err)
	}
	assertSSFStreamEqual(t, got, first)
}

func ssfStreamListActive(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	got, err := b.Streams.ListActive(ctx)
	if err != nil {
		t.Fatalf("ListActive on an empty store: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ListActive on an empty store = %d streams, want 0", len(got))
	}
	for _, s := range []*store.SSFStream{
		ssfStream("stream-enabled", "client-enabled", store.SSFStreamEnabled),
		ssfStream("stream-paused", "client-paused", store.SSFStreamPaused),
		ssfStream("stream-disabled", "client-disabled", store.SSFStreamDisabled),
	} {
		if err := b.Streams.Create(ctx, s); err != nil {
			t.Fatalf("Create %s: %v", s.ID, err)
		}
	}
	got, err = b.Streams.ListActive(ctx)
	if err != nil {
		t.Fatalf("ListActive: %v", err)
	}
	ids := make([]string, 0, len(got))
	for _, s := range got {
		ids = append(ids, s.ID)
	}
	slices.Sort(ids)
	if want := []string{"stream-enabled", "stream-paused"}; !slices.Equal(ids, want) {
		t.Fatalf("ListActive = %v, want %v", ids, want)
	}
}

func ssfStreamUpdate(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	seed := ssfStream("stream-1", "client-1", store.SSFStreamEnabled)
	if err := b.Streams.Create(ctx, seed); err != nil {
		t.Fatalf("Create: %v", err)
	}
	next := ssfStream("stream-1", "client-1", store.SSFStreamPaused)
	next.Delivery = store.SSFDelivery{Method: store.SSFDeliveryPoll}
	next.EventsRequested = []string{"https://schemas.openid.net/secevent/risc/event-type/account-disabled"}
	next.EventsDelivered = nil
	next.Description = "updated"
	next.StatusReason = "maintenance"
	next.UpdatedAt = Reference.Add(time.Hour)
	if err := b.Streams.Update(ctx, next, nil); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := b.Streams.Get(ctx, seed.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertSSFStreamEqual(t, got, next)
}

// ssfStreamUpdateKeepsClient pins that a stream's client binding is
// fixed at Create: Update never rebinds it.
func ssfStreamUpdateKeepsClient(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	seed := ssfStream("stream-1", "client-1", store.SSFStreamEnabled)
	if err := b.Streams.Create(ctx, seed); err != nil {
		t.Fatalf("Create: %v", err)
	}
	next := ssfStream("stream-1", "client-other", store.SSFStreamPaused)
	if err := b.Streams.Update(ctx, next, nil); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := b.Streams.Get(ctx, seed.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ClientID != seed.ClientID {
		t.Fatalf("Update rebound ClientID to %q, want %q", got.ClientID, seed.ClientID)
	}
	byClient, err := b.Streams.GetByClient(ctx, seed.ClientID)
	if err != nil || byClient.ID != seed.ID {
		t.Fatalf("GetByClient(%q) = %v, %v; want the stream", seed.ClientID, byClient, err)
	}
	if _, err := b.Streams.GetByClient(ctx, "client-other"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetByClient(client-other) = %v, want ErrNotFound", err)
	}
}

func ssfStreamDelete(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	s := ssfStream("stream-1", "client-1", store.SSFStreamEnabled)
	if err := b.Streams.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}
	enqueueSSF(t, b,
		ssfEvent("push-1", s.ID, store.SSFEventKindEvent, store.SSFDeliveryPush),
		ssfEvent("verify-1", s.ID, store.SSFEventKindVerification, store.SSFDeliveryPush),
	)
	if err := b.Streams.Delete(ctx, s.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := b.Streams.Get(ctx, s.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Get after Delete = %v, want ErrNotFound", err)
	}
	if _, err := b.Streams.GetByClient(ctx, s.ClientID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("GetByClient after Delete = %v, want ErrNotFound", err)
	}
	assertClaimed(t, b, Reference, nil)
	assertPending(t, b, s.ID, nil)

	// The receiver's one-stream slot is free again.
	if err := b.Streams.Create(ctx, ssfStream("stream-2", s.ClientID, store.SSFStreamEnabled)); err != nil {
		t.Fatalf("Create after Delete: %v", err)
	}
}

func ssfStreamDefensiveCopies(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	seed := ssfStream("stream-1", "client-1", store.SSFStreamEnabled)
	want := ssfStream("stream-1", "client-1", store.SSFStreamEnabled)
	if err := b.Streams.Create(ctx, seed); err != nil {
		t.Fatalf("Create: %v", err)
	}
	seed.EventsRequested[0] = "mutated"
	seed.EventsDelivered[0] = "mutated"
	seed.Delivery.SealedAuthorizationHeader[0] ^= 0xff

	first, err := b.Streams.Get(ctx, want.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	assertSSFStreamEqual(t, first, want)

	first.EventsRequested[0] = "mutated"
	first.EventsDelivered[0] = "mutated"
	first.Delivery.SealedAuthorizationHeader[0] ^= 0xff
	second, err := b.Streams.Get(ctx, want.ID)
	if err != nil {
		t.Fatalf("second Get: %v", err)
	}
	assertSSFStreamEqual(t, second, want)
}

func ssfEnqueueDuplicate(t *testing.T, b SSFBackend) {
	t.Helper()
	enqueueSSF(t, b, ssfEvent("jti-1", "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPoll))
	dup := ssfEvent("jti-1", "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPoll)
	dup.Claims = []byte(`{"jti":"jti-1","dup":true}`)
	if err := b.Events.Enqueue(context.Background(), dup); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("Enqueue duplicate JTI = %v, want ErrAlreadyExists", err)
	}
	got := assertPending(t, b, "stream-1", []string{"jti-1"})
	if want := ssfClaims("jti-1"); !bytes.Equal(got[0].Claims, want) {
		t.Fatalf("Claims after a rejected duplicate = %s, want %s", got[0].Claims, want)
	}
}

// ssfEnqueueControlReplaces pins the one-control-event-per-kind rule: a
// new verification or stream-updated event replaces the queued one of its
// own stream and kind, and leaves other streams and other kinds alone.
func ssfEnqueueControlReplaces(t *testing.T, b SSFBackend) {
	t.Helper()
	enqueueSSF(t, b,
		ssfEvent("verify-old", "stream-1", store.SSFEventKindVerification, store.SSFDeliveryPoll),
		ssfEvent("updated-old", "stream-1", store.SSFEventKindStreamUpdated, store.SSFDeliveryPoll),
		ssfEvent("event-1", "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPoll),
		ssfEvent("verify-other", "stream-2", store.SSFEventKindVerification, store.SSFDeliveryPoll),
		ssfEvent("verify-new", "stream-1", store.SSFEventKindVerification, store.SSFDeliveryPoll),
	)
	assertPending(t, b, "stream-1", []string{"event-1", "updated-old", "verify-new"})
	enqueueSSF(t, b, ssfEvent("updated-new", "stream-1", store.SSFEventKindStreamUpdated, store.SSFDeliveryPoll))
	assertPending(t, b, "stream-1", []string{"event-1", "updated-new", "verify-new"})
	assertPending(t, b, "stream-2", []string{"verify-other"})

	// The same rule holds for a push stream's queue.
	enqueueSSF(t, b,
		ssfEvent("push-verify-old", "stream-3", store.SSFEventKindVerification, store.SSFDeliveryPush),
		ssfEvent("push-verify-new", "stream-3", store.SSFEventKindVerification, store.SSFDeliveryPush),
	)
	assertClaimed(t, b, Reference, []string{"push-verify-new"})
}

// ssfEnqueueMatchesStream pins the stream-state check: an event built
// from a stream read before its state changed is refused, so the caller
// re-reads the stream instead of queueing a SET that escapes a pause or a
// disable, or one tagged for a delivery method nobody reads.
func ssfEnqueueMatchesStream(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	s := ssfStream("stream-1", "client-1", store.SSFStreamPaused)
	if err := b.Streams.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}
	held := func(jti string, kind store.SSFEventKind, delivery store.SSFDeliveryMethod) *store.SSFEvent {
		ev := ssfEvent(jti, s.ID, kind, delivery)
		ev.Held = true
		return ev
	}
	for _, ev := range []*store.SSFEvent{
		ssfEvent("unheld", s.ID, store.SSFEventKindEvent, store.SSFDeliveryPush),
		held("poll-held", store.SSFEventKindEvent, store.SSFDeliveryPoll),
		ssfEvent("poll-verify", s.ID, store.SSFEventKindVerification, store.SSFDeliveryPoll),
	} {
		if err := b.Events.Enqueue(ctx, ev); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("Enqueue %s on a paused push stream = %v, want ErrConflict", ev.JTI, err)
		}
	}
	enqueueSSF(t, b,
		held("held", store.SSFEventKindEvent, store.SSFDeliveryPush),
		ssfEvent("verify", s.ID, store.SSFEventKindVerification, store.SSFDeliveryPush),
	)
	assertClaimed(t, b, Reference, []string{"verify"})

	s.Status = store.SSFStreamDisabled
	if err := b.Streams.Update(ctx, s, nil); err != nil {
		t.Fatalf("Update disabled: %v", err)
	}
	for _, ev := range []*store.SSFEvent{
		ssfEvent("disabled-unheld", s.ID, store.SSFEventKindEvent, store.SSFDeliveryPush),
		held("disabled-held", store.SSFEventKindEvent, store.SSFDeliveryPush),
	} {
		if err := b.Events.Enqueue(ctx, ev); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("Enqueue %s on a disabled stream = %v, want ErrConflict", ev.JTI, err)
		}
	}
	enqueueSSF(t, b, ssfEvent("disabled-updated", s.ID, store.SSFEventKindStreamUpdated, store.SSFDeliveryPush))
	assertClaimed(t, b, Reference, []string{"disabled-updated"})
}

// ssfEnqueueVerificationRace pins the one-verification rule under
// concurrent enqueues on one stream: a backend that inserts and then
// deletes the others in a transaction that cannot see its peers' rows
// keeps several.
func ssfEnqueueVerificationRace(t *testing.T, b SSFBackend) {
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
			return b.Events.Enqueue(ctx, ssfEvent(fmt.Sprintf("verify-%d", i), s.ID, store.SSFEventKindVerification, store.SSFDeliveryPoll))
		})...,
	)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("racing Enqueue %d: %v", i, err)
		}
	}
	got, _, err := b.Events.Pending(ctx, s.ID, 100)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("verifications queued after %d racing enqueues = %v, want exactly one", concurrentRacers, ssfJTIs(got))
	}
}

// ssfEnqueueUpdateRace pins the atomicity of the state check against a
// concurrent pause: every event built for the enabled stream either lands
// before the pause and is held by it, or is refused. None is claimable.
func ssfEnqueueUpdateRace(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	s := ssfStream("stream-1", "client-1", store.SSFStreamEnabled)
	if err := b.Streams.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}
	paused := ssfStream(s.ID, s.ClientID, store.SSFStreamPaused)
	attempts := everyRacer(func(i int) error {
		err := b.Events.Enqueue(ctx, ssfEvent(fmt.Sprintf("event-%d", i), s.ID, store.SSFEventKindEvent, store.SSFDeliveryPush))
		if errors.Is(err, store.ErrConflict) {
			return nil
		}
		return err
	})
	attempts[len(attempts)/2] = func() error { return b.Streams.Update(ctx, paused, nil) }
	errs := race(func() { _, _, _ = b.Events.Pending(ctx, "ssf-race-warmup", 1) }, attempts...)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("racer %d: %v", i, err)
		}
	}
	assertClaimed(t, b, Reference, nil)
}

func ssfClaimDueSelects(t *testing.T, b SSFBackend) {
	t.Helper()
	held := ssfEvent("held", "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPush)
	held.Held = true
	future := ssfEvent("future", "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPush)
	future.NextAttemptAt = Reference.Add(time.Second)
	boundary := ssfEvent("boundary", "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPush)
	boundary.NextAttemptAt = Reference
	due := ssfEvent("due", "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPush)
	due.Attempts = 2
	enqueueSSF(t, b,
		held, future, boundary, due,
		ssfEvent("poll", "stream-2", store.SSFEventKindEvent, store.SSFDeliveryPoll),
		ssfEvent("control", "stream-1", store.SSFEventKindStreamUpdated, store.SSFDeliveryPush),
	)
	got := assertClaimed(t, b, Reference, []string{"boundary", "control", "due"})
	for _, ev := range got {
		if want := Reference.Add(ssfLease); !ev.NextAttemptAt.Equal(want) {
			t.Fatalf("claimed %s NextAttemptAt = %v, want now+lease %v", ev.JTI, ev.NextAttemptAt, want)
		}
		if ev.JTI == "due" {
			if ev.Attempts != 2 {
				t.Fatalf("claimed due Attempts = %d, want 2 (ClaimDue does not count attempts)", ev.Attempts)
			}
			if !bytes.Equal(ev.Claims, ssfClaims("due")) || ev.StreamID != "stream-1" || ev.Kind != store.SSFEventKindEvent {
				t.Fatalf("claimed due = %+v, want the enqueued fields", ev)
			}
		}
	}
}

func ssfClaimDueOrder(t *testing.T, b SSFBackend) {
	t.Helper()
	late := ssfEvent("late", "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPush)
	late.NextAttemptAt = Reference.Add(-time.Minute)
	early := ssfEvent("early", "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPush)
	early.NextAttemptAt = Reference.Add(-time.Hour)
	enqueueSSF(t, b, late, early)
	got, err := b.Events.ClaimDue(context.Background(), Reference, 1, 1, ssfLease)
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	if len(got) != 1 || got[0].JTI != "early" {
		t.Fatalf("ClaimDue(n=1) = %v, want [early]", ssfJTIs(got))
	}
}

// ssfClaimDueStreamCap pins the per-stream cap: a stream whose backlog is
// due before everything else still yields only its share of a claim, the
// other streams' due events fill the rest, and each stream's share is its
// earliest events in order.
func ssfClaimDueStreamCap(t *testing.T, b SSFBackend) {
	t.Helper()
	for i := range 5 {
		ev := ssfEvent(fmt.Sprintf("a-%d", i), "stream-a", store.SSFEventKindEvent, store.SSFDeliveryPush)
		ev.NextAttemptAt = Reference.Add(-time.Hour + time.Duration(i)*time.Minute)
		enqueueSSF(t, b, ev)
	}
	enqueueSSF(t, b,
		ssfEvent("b-0", "stream-b", store.SSFEventKindEvent, store.SSFDeliveryPush),
		ssfEvent("c-0", "stream-c", store.SSFEventKindVerification, store.SSFDeliveryPush),
	)
	ctx := context.Background()
	got, err := b.Events.ClaimDue(ctx, Reference, 3, 1, ssfLease)
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	if jtis := ssfJTIs(got); !slices.Equal(jtis, []string{"a-0", "b-0", "c-0"}) {
		t.Fatalf("ClaimDue(n=3, perStream=1) = %v, want [a-0 b-0 c-0]", jtis)
	}
	got, err = b.Events.ClaimDue(ctx, Reference, 10, 2, ssfLease)
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	if len(got) != 2 || got[0].JTI != "a-1" || got[1].JTI != "a-2" {
		t.Fatalf("ClaimDue(n=10, perStream=2) = %v in claim order, want [a-1 a-2]", ssfJTIs(got))
	}
}

// ssfClaimDueLease pins what the lease means: a claimed event is invisible
// to every claimer until the lease ends, and due again once it has, which
// is how an event whose claimer died gets delivered after all.
func ssfClaimDueLease(t *testing.T, b SSFBackend) {
	t.Helper()
	enqueueSSF(t, b, ssfEvent("jti-1", "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPush))
	assertClaimed(t, b, Reference, []string{"jti-1"})
	assertClaimed(t, b, Reference, nil)
	assertClaimed(t, b, Reference.Add(ssfLease-time.Second), nil)
	got := assertClaimed(t, b, Reference.Add(ssfLease), []string{"jti-1"})
	if want := Reference.Add(2 * ssfLease); !got[0].NextAttemptAt.Equal(want) {
		t.Fatalf("re-claimed NextAttemptAt = %v, want %v", got[0].NextAttemptAt, want)
	}
}

// ssfClaimDueOneWinner pins the single-winner rule
// [store.SSFEventStore.ClaimDue] declares under the traffic it exists
// for: every OP replica's push worker claiming the same due events at
// once. Each event MUST go to exactly one claimer. A backend that selects
// due rows and then writes the lease back in a second step passes every
// sequential case and pushes each SET once per replica.
func ssfClaimDueOneWinner(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	want := []string{"jti-1", "jti-2", "jti-3"}
	for _, jti := range want {
		enqueueSSF(t, b, ssfEvent(jti, "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPush))
	}
	claimed := make([][]*store.SSFEvent, concurrentRacers)
	errs := race(
		func() { _, _, _ = b.Events.Pending(ctx, "ssf-race-warmup", 1) },
		everyRacer(func(i int) error {
			got, err := b.Events.ClaimDue(ctx, Reference, len(want), len(want), ssfLease)
			claimed[i] = got
			return err
		})...,
	)
	all := make([]string, 0, len(want))
	for i, err := range errs {
		if err != nil {
			t.Fatalf("racing ClaimDue %d: %v", i, err)
		}
		all = append(all, ssfJTIs(claimed[i])...)
	}
	slices.Sort(all)
	if !slices.Equal(all, want) {
		t.Fatalf("events claimed across %d racers = %v, want each of %v exactly once", concurrentRacers, all, want)
	}
}

func ssfReschedule(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	enqueueSSF(t, b, ssfEvent("jti-1", "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPush))
	assertClaimed(t, b, Reference, []string{"jti-1"})
	next := Reference.Add(5 * time.Minute)
	if err := b.Events.Reschedule(ctx, "jti-1", next, 1); err != nil {
		t.Fatalf("Reschedule: %v", err)
	}
	assertClaimed(t, b, next.Add(-time.Second), nil)
	got := assertClaimed(t, b, next, []string{"jti-1"})
	if got[0].Attempts != 1 {
		t.Fatalf("Attempts after Reschedule = %d, want 1", got[0].Attempts)
	}
	if err := b.Events.Reschedule(ctx, "missing", next, 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Reschedule(missing) = %v, want ErrNotFound", err)
	}
}

func ssfAck(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	enqueueSSF(t, b,
		ssfEvent("a-1", "stream-a", store.SSFEventKindEvent, store.SSFDeliveryPoll),
		ssfEvent("a-2", "stream-a", store.SSFEventKindEvent, store.SSFDeliveryPoll),
		ssfEvent("b-1", "stream-b", store.SSFEventKindEvent, store.SSFDeliveryPoll),
	)
	// stream-a acknowledges one of its own, one unknown and one of
	// stream-b's: only its own goes.
	if err := b.Events.Ack(ctx, "stream-a", []string{"a-1", "unknown", "b-1"}); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	assertPending(t, b, "stream-a", []string{"a-2"})
	assertPending(t, b, "stream-b", []string{"b-1"})
	if err := b.Events.Ack(ctx, "stream-a", nil); err != nil {
		t.Fatalf("Ack(nil): %v", err)
	}
	if err := b.Events.Ack(ctx, "stream-a", []string{"a-1"}); err != nil {
		t.Fatalf("Ack of an already-acknowledged JTI: %v", err)
	}
	assertPending(t, b, "stream-a", []string{"a-2"})
}

func ssfPending(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	held := ssfEvent("held", "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPoll)
	held.Held = true
	enqueueSSF(t, b,
		ssfEvent("p-1", "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPoll),
		ssfEvent("p-2", "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPoll),
		ssfEvent("p-3", "stream-1", store.SSFEventKindStreamUpdated, store.SSFDeliveryPoll),
		held,
		ssfEvent("push", "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPush),
		ssfEvent("other", "stream-2", store.SSFEventKindEvent, store.SSFDeliveryPoll),
	)
	for _, tc := range []struct {
		n        int
		wantLen  int
		wantMore bool
	}{
		{n: 1, wantLen: 1, wantMore: true},
		{n: 2, wantLen: 2, wantMore: true},
		{n: 3, wantLen: 3, wantMore: false},
		{n: 10, wantLen: 3, wantMore: false},
	} {
		got, more, err := b.Events.Pending(ctx, "stream-1", tc.n)
		if err != nil {
			t.Fatalf("Pending(n=%d): %v", tc.n, err)
		}
		jtis := ssfJTIs(got)
		if len(jtis) != tc.wantLen || more != tc.wantMore {
			t.Fatalf("Pending(n=%d) = %v more=%v, want %d events more=%v", tc.n, jtis, more, tc.wantLen, tc.wantMore)
		}
		for _, jti := range jtis {
			if !slices.Contains([]string{"p-1", "p-2", "p-3"}, jti) {
				t.Fatalf("Pending(n=%d) returned %q, which is held, push-delivered or another stream's", tc.n, jti)
			}
		}
	}
	// Pending does not consume: the events are still there.
	assertPending(t, b, "stream-1", []string{"p-1", "p-2", "p-3"})
	assertPending(t, b, "stream-empty", nil)
}

// ssfUpdateHeld pins the pause rules: pausing a stream holds its ordinary
// events and never its control events, which SSF 1.0 §8.1.5 requires a
// receiver to get whatever the stream's status.
func ssfUpdateHeld(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	s := ssfStream("stream-1", "client-1", store.SSFStreamEnabled)
	if err := b.Streams.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}
	enqueueSSF(t, b,
		ssfEvent("event-1", s.ID, store.SSFEventKindEvent, store.SSFDeliveryPush),
		ssfEvent("updated-1", s.ID, store.SSFEventKindStreamUpdated, store.SSFDeliveryPush),
		ssfEvent("verify-1", s.ID, store.SSFEventKindVerification, store.SSFDeliveryPush),
		ssfEvent("other-1", "stream-2", store.SSFEventKindEvent, store.SSFDeliveryPush),
	)
	s.Status = store.SSFStreamPaused
	if err := b.Streams.Update(ctx, s, nil); err != nil {
		t.Fatalf("Update paused: %v", err)
	}
	assertClaimed(t, b, Reference, []string{"other-1", "updated-1", "verify-1"})

	s.Status = store.SSFStreamEnabled
	if err := b.Streams.Update(ctx, s, nil); err != nil {
		t.Fatalf("Update enabled: %v", err)
	}
	assertClaimed(t, b, Reference, []string{"event-1"})
}

// ssfUpdateDelivery pins a delivery-method change: every queued event of
// the stream, control events included, moves to the new method.
func ssfUpdateDelivery(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	s := ssfStream("stream-1", "client-1", store.SSFStreamEnabled)
	if err := b.Streams.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}
	enqueueSSF(t, b,
		ssfEvent("event-1", s.ID, store.SSFEventKindEvent, store.SSFDeliveryPush),
		ssfEvent("verify-1", s.ID, store.SSFEventKindVerification, store.SSFDeliveryPush),
		ssfEvent("other-1", "stream-2", store.SSFEventKindEvent, store.SSFDeliveryPush),
	)
	s.Delivery = store.SSFDelivery{Method: store.SSFDeliveryPoll}
	if err := b.Streams.Update(ctx, s, nil); err != nil {
		t.Fatalf("Update to poll: %v", err)
	}
	got := assertPending(t, b, s.ID, []string{"event-1", "verify-1"})
	for _, ev := range got {
		if ev.Delivery != store.SSFDeliveryPoll || ev.Held {
			t.Fatalf("moved %s = Delivery %q Held %v, want poll and unheld", ev.JTI, ev.Delivery, ev.Held)
		}
	}
	assertClaimed(t, b, Reference, []string{"other-1"})

	// Pausing a poll stream hides its ordinary events from Pending.
	s.Status = store.SSFStreamPaused
	if err := b.Streams.Update(ctx, s, nil); err != nil {
		t.Fatalf("Update poll paused: %v", err)
	}
	assertPending(t, b, s.ID, []string{"verify-1"})
}

// ssfUpdateDisabled pins the disable rule: a disabled stream's ordinary
// events are dropped, not held, and its control events stay queued.
func ssfUpdateDisabled(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	s := ssfStream("stream-1", "client-1", store.SSFStreamEnabled)
	s.Delivery = store.SSFDelivery{Method: store.SSFDeliveryPoll}
	if err := b.Streams.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}
	enqueueSSF(t, b,
		ssfEvent("event-1", s.ID, store.SSFEventKindEvent, store.SSFDeliveryPoll),
		ssfEvent("updated-1", s.ID, store.SSFEventKindStreamUpdated, store.SSFDeliveryPoll),
		ssfEvent("verify-1", s.ID, store.SSFEventKindVerification, store.SSFDeliveryPoll),
		ssfEvent("other-1", "stream-2", store.SSFEventKindEvent, store.SSFDeliveryPoll),
	)
	s.Status = store.SSFStreamDisabled
	if err := b.Streams.Update(ctx, s, nil); err != nil {
		t.Fatalf("Update disabled: %v", err)
	}
	assertPending(t, b, s.ID, []string{"updated-1", "verify-1"})
	s.Status = store.SSFStreamEnabled
	if err := b.Streams.Update(ctx, s, nil); err != nil {
		t.Fatalf("Update enabled: %v", err)
	}
	assertPending(t, b, s.ID, []string{"updated-1", "verify-1"})
	assertPending(t, b, "stream-2", []string{"other-1"})
}

// ssfUpdateNotice pins the stream-updated notice an Update carries: it is
// stored with the state change and replaces the stream's pending one, so
// toggling a stream's status costs a bounded queue. A notice whose JTI is
// taken, or an Update of a missing stream, changes nothing.
func ssfUpdateNotice(t *testing.T, b SSFBackend) {
	t.Helper()
	ctx := context.Background()
	s := ssfStream("stream-1", "client-1", store.SSFStreamEnabled)
	s.Delivery = store.SSFDelivery{Method: store.SSFDeliveryPoll}
	if err := b.Streams.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}
	enqueueSSF(t, b,
		ssfEvent("updated-old", s.ID, store.SSFEventKindStreamUpdated, store.SSFDeliveryPoll),
		ssfEvent("verify-1", s.ID, store.SSFEventKindVerification, store.SSFDeliveryPoll),
	)
	for i, status := range []store.SSFStreamStatus{store.SSFStreamPaused, store.SSFStreamEnabled, store.SSFStreamPaused} {
		s.Status = status
		notice := ssfEvent(fmt.Sprintf("updated-%d", i), s.ID, store.SSFEventKindStreamUpdated, store.SSFDeliveryPoll)
		if err := b.Streams.Update(ctx, s, notice); err != nil {
			t.Fatalf("Update %s: %v", status, err)
		}
	}
	assertPending(t, b, s.ID, []string{"updated-2", "verify-1"})

	s.Status = store.SSFStreamDisabled
	dup := ssfEvent("verify-1", s.ID, store.SSFEventKindStreamUpdated, store.SSFDeliveryPoll)
	if err := b.Streams.Update(ctx, s, dup); !errors.Is(err, store.ErrAlreadyExists) {
		t.Fatalf("Update with a taken notice JTI = %v, want ErrAlreadyExists", err)
	}
	got, err := b.Streams.Get(ctx, s.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != store.SSFStreamPaused {
		t.Fatalf("Status after a refused Update = %q, want paused", got.Status)
	}
	assertPending(t, b, s.ID, []string{"updated-2", "verify-1"})

	orphan := ssfEvent("updated-orphan", "missing", store.SSFEventKindStreamUpdated, store.SSFDeliveryPoll)
	if err := b.Streams.Update(ctx, ssfStream("missing", "client-missing", store.SSFStreamEnabled), orphan); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("Update(missing) with a notice = %v, want ErrNotFound", err)
	}
	assertPending(t, b, "missing", nil)
}

func ssfDeleteExpired(t *testing.T, b SSFBackend) {
	t.Helper()
	past := ssfEvent("past", "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPoll)
	past.ExpiresAt = Reference.Add(-time.Second)
	boundary := ssfEvent("boundary", "stream-1", store.SSFEventKindVerification, store.SSFDeliveryPoll)
	boundary.ExpiresAt = Reference
	live := ssfEvent("live", "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPoll)
	live.ExpiresAt = Reference.Add(time.Second)
	held := ssfEvent("held", "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPoll)
	held.Held = true
	held.ExpiresAt = Reference.Add(-time.Hour)
	enqueueSSF(t, b, past, boundary, live, held)
	ctx := context.Background()
	s := ssfStream("stream-1", "client-1", store.SSFStreamEnabled)
	s.Delivery = store.SSFDelivery{Method: store.SSFDeliveryPoll}
	if err := b.Streams.Create(ctx, s); err != nil {
		t.Fatalf("Create: %v", err)
	}

	n, err := b.Events.DeleteExpired(ctx, Reference)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if n != 3 {
		t.Fatalf("DeleteExpired = %d, want 3", n)
	}
	assertPending(t, b, "stream-1", []string{"live"})
	// Releasing the hold shows the expired held event is gone too.
	if err := b.Streams.Update(ctx, s, nil); err != nil {
		t.Fatalf("Update: %v", err)
	}
	assertPending(t, b, "stream-1", []string{"live"})
}

func ssfEventDefensiveCopies(t *testing.T, b SSFBackend) {
	t.Helper()
	ev := ssfEvent("jti-1", "stream-1", store.SSFEventKindEvent, store.SSFDeliveryPoll)
	enqueueSSF(t, b, ev)
	ev.Claims[0] ^= 0xff

	first := assertPending(t, b, "stream-1", []string{"jti-1"})
	if !bytes.Equal(first[0].Claims, ssfClaims("jti-1")) {
		t.Fatalf("Enqueue input mutation leaked into Claims: %s", first[0].Claims)
	}
	first[0].Claims[0] ^= 0xff
	second := assertPending(t, b, "stream-1", []string{"jti-1"})
	if !bytes.Equal(second[0].Claims, ssfClaims("jti-1")) {
		t.Fatalf("Pending result mutation leaked into Claims: %s", second[0].Claims)
	}
}

func ssfStream(id, clientID string, status store.SSFStreamStatus) *store.SSFStream {
	return &store.SSFStream{
		ID:       id,
		ClientID: clientID,
		Delivery: store.SSFDelivery{
			Method:                    store.SSFDeliveryPush,
			EndpointURL:               "https://receiver.example.com/events",
			SealedAuthorizationHeader: []byte{0x01, 0x02, 0xfe, 0xff},
		},
		EventsRequested: []string{
			"https://schemas.openid.net/secevent/caep/event-type/session-revoked",
			"https://schemas.openid.net/secevent/caep/event-type/credential-change",
		},
		EventsDelivered: []string{"https://schemas.openid.net/secevent/caep/event-type/session-revoked"},
		Description:     "contract stream",
		Status:          status,
		StatusReason:    "",
		CreatedAt:       Reference.Add(-time.Hour),
		UpdatedAt:       Reference.Add(-time.Minute),
	}
}

func ssfClaims(jti string) []byte { return []byte(`{"jti":"` + jti + `"}`) }

// ssfEvent builds an unheld event due a minute before [Reference] and
// expiring a week after it.
func ssfEvent(jti, streamID string, kind store.SSFEventKind, delivery store.SSFDeliveryMethod) *store.SSFEvent {
	return &store.SSFEvent{
		JTI:           jti,
		StreamID:      streamID,
		Kind:          kind,
		Delivery:      delivery,
		Claims:        ssfClaims(jti),
		NextAttemptAt: Reference.Add(-time.Minute),
		ExpiresAt:     Reference.Add(7 * 24 * time.Hour),
	}
}

func enqueueSSF(t *testing.T, b SSFBackend, events ...*store.SSFEvent) {
	t.Helper()
	for _, ev := range events {
		if err := b.Events.Enqueue(context.Background(), ev); err != nil {
			t.Fatalf("Enqueue %s: %v", ev.JTI, err)
		}
	}
}

func ssfJTIs(events []*store.SSFEvent) []string {
	out := make([]string, 0, len(events))
	for _, ev := range events {
		out = append(out, ev.JTI)
	}
	slices.Sort(out)
	return out
}

// assertClaimed claims every due event at now and fails unless the
// claimed JTIs are exactly want.
func assertClaimed(t *testing.T, b SSFBackend, now time.Time, want []string) []*store.SSFEvent {
	t.Helper()
	got, err := b.Events.ClaimDue(context.Background(), now, 100, 100, ssfLease)
	if err != nil {
		t.Fatalf("ClaimDue at %v: %v", now, err)
	}
	if jtis := ssfJTIs(got); !slices.Equal(jtis, want) {
		t.Fatalf("ClaimDue at %v = %v, want %v", now, jtis, want)
	}
	return got
}

// assertPending reads every pending poll event of streamID and fails
// unless the JTIs are exactly want.
func assertPending(t *testing.T, b SSFBackend, streamID string, want []string) []*store.SSFEvent {
	t.Helper()
	got, more, err := b.Events.Pending(context.Background(), streamID, 100)
	if err != nil {
		t.Fatalf("Pending(%s): %v", streamID, err)
	}
	if more {
		t.Fatalf("Pending(%s, 100) reported more", streamID)
	}
	if jtis := ssfJTIs(got); !slices.Equal(jtis, want) {
		t.Fatalf("Pending(%s) = %v, want %v", streamID, jtis, want)
	}
	return got
}

func assertSSFStreamEqual(t *testing.T, got, want *store.SSFStream) {
	t.Helper()
	switch {
	case got.ID != want.ID, got.ClientID != want.ClientID:
		t.Fatalf("stream identity = %q/%q, want %q/%q", got.ID, got.ClientID, want.ID, want.ClientID)
	case got.Delivery.Method != want.Delivery.Method,
		got.Delivery.EndpointURL != want.Delivery.EndpointURL,
		!bytes.Equal(got.Delivery.SealedAuthorizationHeader, want.Delivery.SealedAuthorizationHeader):
		t.Fatalf("Delivery = %+v, want %+v", got.Delivery, want.Delivery)
	case !slices.Equal(got.EventsRequested, want.EventsRequested):
		t.Fatalf("EventsRequested = %v, want %v", got.EventsRequested, want.EventsRequested)
	case !slices.Equal(got.EventsDelivered, want.EventsDelivered):
		t.Fatalf("EventsDelivered = %v, want %v", got.EventsDelivered, want.EventsDelivered)
	case got.Description != want.Description:
		t.Fatalf("Description = %q, want %q", got.Description, want.Description)
	case got.Status != want.Status, got.StatusReason != want.StatusReason:
		t.Fatalf("Status = %q/%q, want %q/%q", got.Status, got.StatusReason, want.Status, want.StatusReason)
	case !got.CreatedAt.Equal(want.CreatedAt), !got.UpdatedAt.Equal(want.UpdatedAt):
		t.Fatalf("timestamps = %v/%v, want %v/%v", got.CreatedAt, got.UpdatedAt, want.CreatedAt, want.UpdatedAt)
	}
}
