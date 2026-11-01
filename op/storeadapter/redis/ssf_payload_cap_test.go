//nolint:testpackage // exercises the unexported payload cap without a Redis server.
package oidcredis

import (
	"context"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// TestSSFEnqueue_RejectsOversizedClaims pins that event claims are held to
// the same value cap as every other writer; the check runs before any
// network call.
func TestSSFEnqueue_RejectsOversizedClaims(t *testing.T) {
	t.Parallel()
	events := &ssfEventStore{parent: &Store{maxValueBytes: 1024}}
	err := events.Enqueue(context.Background(), &store.SSFEvent{
		JTI:      "jti-1",
		StreamID: "stream-1",
		Kind:     store.SSFEventKindEvent,
		Delivery: store.SSFDeliveryPoll,
		Claims:   []byte(strings.Repeat("x", 2048)),
	})
	if err == nil || !strings.Contains(err.Error(), "ssf event payload") {
		t.Fatalf("Enqueue oversized claims error = %v, want payload cap error", err)
	}
}
