//go:build testcontainers

package oidcdynamo_test

import (
	"context"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
)

// ssfLaggingIndexAPI stands in for global secondary indexes that have not
// caught up with any write: every index Query that is not strongly
// consistent comes back empty and is counted. A consistent index Query
// can only be a local secondary index, which never lags.
type ssfLaggingIndexAPI struct {
	oidcdynamo.API
	stale *atomic.Int64
}

func (a ssfLaggingIndexAPI) Query(
	ctx context.Context,
	in *awsdynamodb.QueryInput,
	opts ...func(*awsdynamodb.Options),
) (*awsdynamodb.QueryOutput, error) {
	out, err := a.API.Query(ctx, in, opts...)
	if err != nil || in.IndexName == nil || (in.ConsistentRead != nil && *in.ConsistentRead) {
		return out, err
	}
	a.stale.Add(1)
	out.Items = nil
	out.LastEvaluatedKey = nil
	return out, nil
}

// TestSSF_QueueReadsSeeEventsTheIndexesDoNotShow enqueues events and at
// once moves, reads and deletes the stream's queue while no global index
// shows them: every step still sees every committed event, and none of
// them reads an eventually consistent index.
func TestSSF_QueueReadsSeeEventsTheIndexesDoNotShow(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	client := newEmulatorClient(t)
	var stale atomic.Int64
	s, err := oidcdynamo.New(ssfLaggingIndexAPI{API: client, stale: &stale},
		oidcdynamo.WithTablePrefix("ssflag_"),
		oidcdynamo.WithClock(&fixedClock{now: contract.Reference}),
	)
	if err != nil {
		t.Fatalf("oidcdynamo.New: %v", err)
	}
	if err := s.CreateTables(ctx); err != nil {
		t.Fatalf("CreateTables: %v", err)
	}
	disableEmulatorTTL(t, client, s)
	streams, events := s.SSFStreams(), s.SSFEvents()

	st := &store.SSFStream{
		ID:       "stream-1",
		ClientID: "client-1",
		Delivery: store.SSFDelivery{Method: store.SSFDeliveryPush, EndpointURL: "https://receiver.example.com/events"},
		Status:   store.SSFStreamEnabled,
	}
	if err := streams.Create(ctx, st); err != nil {
		t.Fatalf("Create: %v", err)
	}
	for _, ev := range []*store.SSFEvent{
		ssfLagEvent("event-1", st.ID, store.SSFEventKindEvent),
		ssfLagEvent("event-2", st.ID, store.SSFEventKindEvent),
		ssfLagEvent("verify-1", st.ID, store.SSFEventKindVerification),
	} {
		if err := events.Enqueue(ctx, ev); err != nil {
			t.Fatalf("Enqueue %s: %v", ev.JTI, err)
		}
	}

	st.Delivery = store.SSFDelivery{Method: store.SSFDeliveryPoll}
	if err := streams.Update(ctx, st, nil); err != nil {
		t.Fatalf("Update to poll: %v", err)
	}
	ssfLagPending(t, events, st.ID, "event-1", "event-2", "verify-1")

	st.Status = store.SSFStreamPaused
	if err := streams.Update(ctx, st, nil); err != nil {
		t.Fatalf("Update paused: %v", err)
	}
	ssfLagPending(t, events, st.ID, "verify-1")

	st.Status = store.SSFStreamEnabled
	if err := streams.Update(ctx, st, nil); err != nil {
		t.Fatalf("Update enabled: %v", err)
	}
	ssfLagPending(t, events, st.ID, "event-1", "event-2", "verify-1")

	if err := events.Ack(ctx, st.ID, []string{"event-2"}); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	ssfLagPending(t, events, st.ID, "event-1", "verify-1")

	if err := streams.Delete(ctx, st.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	ssfLagPending(t, events, st.ID)
	// Delete released every JTI the stream held.
	for _, jti := range []string{"event-1", "verify-1"} {
		if err := events.Enqueue(ctx, ssfLagEvent(jti, "stream-2", store.SSFEventKindEvent)); err != nil {
			t.Fatalf("Enqueue %s after its stream was deleted: %v", jti, err)
		}
	}
	if got := stale.Load(); got != 0 {
		t.Fatalf("queue operations read an eventually consistent index %d times, want 0", got)
	}
}

func ssfLagEvent(jti, streamID string, kind store.SSFEventKind) *store.SSFEvent {
	return &store.SSFEvent{
		JTI:           jti,
		StreamID:      streamID,
		Kind:          kind,
		Delivery:      store.SSFDeliveryPush,
		Claims:        []byte(`{"jti":"` + jti + `"}`),
		NextAttemptAt: contract.Reference,
		ExpiresAt:     contract.Reference.Add(time.Hour),
	}
}

func ssfLagPending(t *testing.T, events store.SSFEventStore, streamID string, want ...string) {
	t.Helper()
	got, more, err := events.Pending(t.Context(), streamID, 100)
	if err != nil {
		t.Fatalf("Pending: %v", err)
	}
	jtis := make([]string, 0, len(got))
	for _, ev := range got {
		jtis = append(jtis, ev.JTI)
	}
	slices.Sort(jtis)
	if more || !slices.Equal(jtis, want) {
		t.Fatalf("Pending = %v more=%v, want %v", jtis, more, want)
	}
}
