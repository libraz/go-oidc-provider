package oidcsql_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// TestSQLite_SSFAckSpansBatches acknowledges more JTIs than one statement
// binds and checks that every one is removed while a sibling stream's
// events survive.
func TestSQLite_SSFAckSpansBatches(t *testing.T) {
	t.Parallel()

	b := newSQLiteFactory(t)(t)
	ss, ok := b.Store.(store.SharedSignalsStore)
	if !ok {
		t.Fatal("sql store does not implement store.SharedSignalsStore")
	}
	events := ss.SSFEvents()
	ctx := context.Background()
	const total = 1203
	jtis := make([]string, 0, total)
	for i := range total {
		jti := fmt.Sprintf("jti-%04d", i)
		jtis = append(jtis, jti)
		if err := events.Enqueue(ctx, &store.SSFEvent{
			JTI: jti, StreamID: "a", Kind: store.SSFEventKindEvent, Delivery: store.SSFDeliveryPoll,
			Claims: []byte(`{}`), NextAttemptAt: b.Now(), ExpiresAt: b.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("Enqueue(%s): %v", jti, err)
		}
	}
	if err := events.Enqueue(ctx, &store.SSFEvent{
		JTI: "other", StreamID: "b", Kind: store.SSFEventKindEvent, Delivery: store.SSFDeliveryPoll,
		Claims: []byte(`{}`), NextAttemptAt: b.Now(), ExpiresAt: b.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Enqueue(other): %v", err)
	}
	if err := events.Ack(ctx, "b", jtis); err != nil {
		t.Fatalf("Ack on the wrong stream: %v", err)
	}
	if err := events.Ack(ctx, "a", append(jtis, "other")); err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if got, _, err := events.Pending(ctx, "a", 10); err != nil || len(got) != 0 {
		t.Fatalf("Pending(a) = %d events, err %v; want none", len(got), err)
	}
	if got, _, err := events.Pending(ctx, "b", 10); err != nil || len(got) != 1 {
		t.Fatalf("Pending(b) = %d events, err %v; want the sibling stream's event", len(got), err)
	}
}
