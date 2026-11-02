//go:build testcontainers

package oidcdynamo_test

import (
	"context"
	"fmt"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	awsdynamodb "github.com/aws/aws-sdk-go-v2/service/dynamodb"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcdynamo "github.com/libraz/go-oidc-provider/op/storeadapter/dynamodb"
)

// ssfIndexReadAPI counts the items every secondary-index Query returns.
type ssfIndexReadAPI struct {
	oidcdynamo.API
	read *atomic.Int64
}

func (a ssfIndexReadAPI) Query(
	ctx context.Context,
	in *awsdynamodb.QueryInput,
	opts ...func(*awsdynamodb.Options),
) (*awsdynamodb.QueryOutput, error) {
	out, err := a.API.Query(ctx, in, opts...)
	if err == nil && in.IndexName != nil {
		a.read.Add(int64(len(out.Items)))
	}
	return out, err
}

// TestSSF_ClaimDueReadsNoBacklogPastAStreamsShare queues one stream's
// large due backlog ahead of two other streams' due events: a claim
// taking one event per stream reads a stream's share of index entries,
// not the backlog it passes over.
func TestSSF_ClaimDueReadsNoBacklogPastAStreamsShare(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	client := newEmulatorClient(t)
	var read atomic.Int64
	s, err := oidcdynamo.New(ssfIndexReadAPI{API: client, read: &read},
		oidcdynamo.WithTablePrefix("ssfclaim_"),
		oidcdynamo.WithClock(&fixedClock{now: contract.Reference}),
	)
	if err != nil {
		t.Fatalf("oidcdynamo.New: %v", err)
	}
	if err := s.CreateTables(ctx); err != nil {
		t.Fatalf("CreateTables: %v", err)
	}
	disableEmulatorTTL(t, client, s)
	events := s.SSFEvents()

	const backlog = 120
	for i := range backlog {
		ev := ssfClaimEvent(fmt.Sprintf("a-%03d", i), "stream-a", contract.Reference.Add(-time.Hour+time.Duration(i)*time.Second))
		if err := events.Enqueue(ctx, ev); err != nil {
			t.Fatalf("Enqueue %s: %v", ev.JTI, err)
		}
	}
	for _, ev := range []*store.SSFEvent{
		ssfClaimEvent("b-0", "stream-b", contract.Reference.Add(-time.Minute)),
		ssfClaimEvent("c-0", "stream-c", contract.Reference.Add(-time.Minute)),
		ssfClaimEvent("c-1", "stream-c", contract.Reference.Add(-time.Second)),
	} {
		if err := events.Enqueue(ctx, ev); err != nil {
			t.Fatalf("Enqueue %s: %v", ev.JTI, err)
		}
	}

	read.Store(0)
	got, err := events.ClaimDue(ctx, contract.Reference, 3, 1, time.Minute)
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	jtis := make([]string, 0, len(got))
	for _, ev := range got {
		jtis = append(jtis, ev.JTI)
	}
	slices.Sort(jtis)
	if want := []string{"a-000", "b-0", "c-0"}; !slices.Equal(jtis, want) {
		t.Fatalf("ClaimDue(n=3, perStream=1) = %v, want %v", jtis, want)
	}
	// One entry per stream: its share of one.
	if n := read.Load(); n > 3 {
		t.Fatalf("ClaimDue read %d index entries for 3 streams with a share of 1, want at most 3", n)
	}
}

func ssfClaimEvent(jti, streamID string, next time.Time) *store.SSFEvent {
	return &store.SSFEvent{
		JTI:           jti,
		StreamID:      streamID,
		Kind:          store.SSFEventKindEvent,
		Delivery:      store.SSFDeliveryPush,
		Claims:        []byte(`{"jti":"` + jti + `"}`),
		NextAttemptAt: next,
		ExpiresAt:     contract.Reference.Add(time.Hour),
	}
}
