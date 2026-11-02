package composite_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/composite"
)

// oldKinds are the Kinds that predate the Shared Signals substores.
var oldKinds = []composite.Kind{
	composite.Clients, composite.AuthorizationCodes, composite.RefreshTokens,
	composite.Grants, composite.Sessions, composite.PushedAuthRequests,
	composite.Interactions, composite.ConsumedJTIs, composite.Users,
	composite.InitialAccessTokens, composite.RegistrationAccessTokens,
	composite.AccessTokens, composite.OpaqueAccessTokens,
	composite.GrantRevocations, composite.Metadata, composite.DeviceCodes,
	composite.CIBARequests,
}

func TestSSF_UnroutedFallsBackToClients(t *testing.T) {
	t.Parallel()
	backend := newInmem(t)
	opts := make([]composite.Option, 0, len(oldKinds))
	for _, k := range oldKinds {
		opts = append(opts, composite.With(k, backend))
	}
	s, err := composite.New(opts...)
	if err != nil {
		t.Fatalf("New without WithDefault routing only the original Kinds: %v", err)
	}
	if s.SSFStreams() == nil || s.SSFEvents() == nil {
		t.Fatal("SSF substores must resolve through the Clients backend")
	}
}

func TestSSF_FollowsExplicitRoute(t *testing.T) {
	t.Parallel()
	def := newInmem(t)
	ssf := newInmem(t)
	s, err := composite.New(
		composite.WithDefault(def),
		composite.With(composite.SSFStreams, ssf),
		composite.With(composite.SSFEvents, ssf),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.SSFStreams() != ssf.SSFStreams() || s.SSFEvents() != ssf.SSFEvents() {
		t.Fatal("SSF substores must follow their own routes")
	}
}

func TestSSF_NonImplementingBackendYieldsNil(t *testing.T) {
	t.Parallel()
	ro := newReadOnlyStore(t)
	s, err := composite.New(
		composite.WithDefault(newInmem(t)),
		composite.With(composite.SSFStreams, ro),
		composite.With(composite.SSFEvents, ro),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.SSFStreams() != nil || s.SSFEvents() != nil {
		t.Fatal("backend without SharedSignalsStore must yield nil substores")
	}
}

// TestSSF_SplitRoutingRefused pins that the stream and event substores
// cannot be routed apart: a backend's stream Delete cascades only into its
// own queue, so a split would leave a deleted stream's events behind.
func TestSSF_SplitRoutingRefused(t *testing.T) {
	t.Parallel()
	def := newInmem(t)
	for name, opts := range map[string][]composite.Option{
		"streams elsewhere": {composite.WithDefault(def), composite.With(composite.SSFStreams, newInmem(t))},
		"events elsewhere":  {composite.WithDefault(def), composite.With(composite.SSFEvents, newInmem(t))},
		"both elsewhere": {
			composite.WithDefault(def),
			composite.With(composite.SSFStreams, newInmem(t)),
			composite.With(composite.SSFEvents, newInmem(t)),
		},
	} {
		if _, err := composite.New(opts...); !errors.Is(err, composite.ErrSSFSplit) {
			t.Errorf("%s: New = %v, want ErrSSFSplit", name, err)
		}
	}
}

// TestSSF_DeleteCascadesThroughRoutedEvents pins the Delete cascade on the
// substores the composite hands out: once a stream is deleted, the event
// store the OP reads holds nothing for it.
func TestSSF_DeleteCascadesThroughRoutedEvents(t *testing.T) {
	t.Parallel()
	ssf := newInmem(t)
	s, err := composite.New(
		composite.WithDefault(newInmem(t)),
		composite.With(composite.SSFStreams, ssf),
		composite.With(composite.SSFEvents, ssf),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	stream := &store.SSFStream{
		ID: "stream-1", ClientID: "rp", Status: store.SSFStreamEnabled,
		Delivery: store.SSFDelivery{Method: store.SSFDeliveryPoll},
	}
	if err := s.SSFStreams().Create(ctx, stream); err != nil {
		t.Fatalf("Create: %v", err)
	}
	ev := &store.SSFEvent{
		JTI: "jti-1", StreamID: stream.ID, Kind: store.SSFEventKindEvent, Delivery: store.SSFDeliveryPoll,
		Claims: []byte(`{}`), NextAttemptAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := s.SSFEvents().Enqueue(ctx, ev); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := s.SSFStreams().Delete(ctx, stream.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, _, err := s.SSFEvents().Pending(ctx, stream.ID, 10)
	if err != nil || len(got) != 0 {
		t.Fatalf("Pending after Delete = %d events, %v; want none", len(got), err)
	}
	if n, err := s.SSFEvents().DeleteExpired(ctx, now.Add(2*time.Hour)); err != nil || n != 0 {
		t.Fatalf("DeleteExpired after Delete = %d, %v; want nothing left behind", n, err)
	}
}
