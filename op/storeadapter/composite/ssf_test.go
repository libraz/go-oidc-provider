package composite_test

import (
	"testing"

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
	s, err := composite.New(
		composite.WithDefault(newInmem(t)),
		composite.With(composite.SSFStreams, newReadOnlyStore(t)),
		composite.With(composite.SSFEvents, newReadOnlyStore(t)),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s.SSFStreams() != nil || s.SSFEvents() != nil {
		t.Fatal("backend without SharedSignalsStore must yield nil substores")
	}
}
