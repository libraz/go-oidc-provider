package oidcsql_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// ssfClaimStreams spans several pages of the due-heads walk.
const ssfClaimStreams = 1100

// TestSQLite_SSFClaimDueSpansEveryStream queues one due event on each of
// more streams than one page of the heads walk visits, the earliest on the
// last stream ID: the claim still reaches it and takes the earliest heads.
func TestSQLite_SSFClaimDueSpansEveryStream(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	s, err := oidcsql.New(openSQLite(t), oidcsql.SQLite(), oidcsql.WithClock(&fixedClock{now: contract.Reference}))
	if err != nil {
		t.Fatalf("oidcsql.New: %v", err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	events := s.SSFEvents()
	for i := range ssfClaimStreams {
		ev := ssfClaimEvent(fmt.Sprintf("j-%04d", i), fmt.Sprintf("s-%04d", i), contract.Reference.Add(-time.Duration(i)*time.Second))
		if err := events.Enqueue(ctx, ev); err != nil {
			t.Fatalf("Enqueue %s: %v", ev.JTI, err)
		}
	}
	got, err := events.ClaimDue(ctx, contract.Reference, 2, 1, time.Minute)
	if err != nil {
		t.Fatalf("ClaimDue: %v", err)
	}
	first, second := fmt.Sprintf("j-%04d", ssfClaimStreams-1), fmt.Sprintf("j-%04d", ssfClaimStreams-2)
	if len(got) != 2 || got[0].JTI != first || got[1].JTI != second {
		t.Fatalf("ClaimDue(n=2) over %d streams = %v, want %s then %s", ssfClaimStreams, got, first, second)
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
