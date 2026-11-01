package inmem_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestSSFPendingPagesInJTIOrder pins that Pending returns the lowest JTIs
// first, so successive pages are stable.
func TestSSFPendingPagesInJTIOrder(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	events := inmem.New().SSFEvents()
	at := time.Unix(1_700_000_000, 0)
	for _, jti := range []string{"e", "b", "d", "a", "c"} {
		if err := events.Enqueue(ctx, &store.SSFEvent{
			JTI: jti, StreamID: "s", Kind: store.SSFEventKindEvent, Delivery: store.SSFDeliveryPoll,
			Claims: []byte(`{}`), NextAttemptAt: at, ExpiresAt: at.Add(time.Hour),
		}); err != nil {
			t.Fatalf("Enqueue(%s): %v", jti, err)
		}
	}
	for range 20 {
		got, more, err := events.Pending(ctx, "s", 3)
		if err != nil {
			t.Fatalf("Pending: %v", err)
		}
		jtis := make([]string, 0, len(got))
		for _, ev := range got {
			jtis = append(jtis, ev.JTI)
		}
		if !more || !slices.Equal(jtis, []string{"a", "b", "c"}) {
			t.Fatalf("Pending(3) = %v more=%v, want [a b c] more=true", jtis, more)
		}
	}
}
