package composite_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/composite"
)

var _ store.AuthnLockoutProvider = (*composite.Store)(nil)

func TestStore_AuthnLockouts(t *testing.T) {
	t.Parallel()

	t.Run("default backend with the method", func(t *testing.T) {
		t.Parallel()
		backend := newInmem(t)
		s, err := composite.New(composite.WithDefault(backend))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if got := s.AuthnLockouts(); got == nil || got != backend.AuthnLockouts() {
			t.Fatalf("AuthnLockouts = %v, want the default backend's store", got)
		}
	})

	t.Run("routed to a different backend", func(t *testing.T) {
		t.Parallel()
		def := newInmem(t)
		durable := newInmem(t)
		s, err := composite.New(
			composite.WithDefault(def),
			composite.With(composite.AuthnLockouts, durable),
		)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if s.AuthnLockouts() != durable.AuthnLockouts() {
			t.Fatal("AuthnLockouts must follow the AuthnLockouts route, not the default")
		}
	})

	t.Run("unrouted without a default falls back to Clients", func(t *testing.T) {
		t.Parallel()
		clients := newInmem(t)
		kinds := []composite.Kind{
			composite.Clients, composite.AuthorizationCodes, composite.RefreshTokens,
			composite.Grants, composite.Sessions, composite.PushedAuthRequests,
			composite.Interactions, composite.ConsumedJTIs,
			composite.InitialAccessTokens, composite.RegistrationAccessTokens,
			composite.AccessTokens, composite.OpaqueAccessTokens,
			composite.GrantRevocations, composite.Metadata, composite.DeviceCodes,
			composite.CIBARequests,
		}
		opts := make([]composite.Option, 0, len(kinds))
		for _, k := range kinds {
			opts = append(opts, composite.With(k, clients))
		}
		s, err := composite.New(opts...)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if s.AuthnLockouts() != clients.AuthnLockouts() {
			t.Fatal("unrouted AuthnLockouts must resolve to the Clients backend")
		}
	})

	t.Run("backend without the method", func(t *testing.T) {
		t.Parallel()
		s, err := composite.New(
			composite.WithDefault(newInmem(t)),
			composite.With(composite.AuthnLockouts, newReadOnlyStore(t)),
		)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if got := s.AuthnLockouts(); got != nil {
			t.Fatalf("AuthnLockouts must be nil when the backend lacks the method, got %T", got)
		}
	})
}
