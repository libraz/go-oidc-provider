package composite_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op/storeadapter/composite"
)

func TestStore_AuthnLockouts(t *testing.T) {
	t.Parallel()

	t.Run("users backend with the method", func(t *testing.T) {
		t.Parallel()
		backend := newInmem(t)
		s, err := composite.New(composite.WithDefault(backend))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		got := s.AuthnLockouts()
		if got == nil {
			t.Fatal("AuthnLockouts must be non-nil when the Users backend supports it")
		}
		if got != backend.AuthnLockouts() {
			t.Fatal("AuthnLockouts must return the Users backend's store")
		}
	})

	t.Run("users routed to a different backend", func(t *testing.T) {
		t.Parallel()
		def := newInmem(t)
		users := newInmem(t)
		s, err := composite.New(
			composite.WithDefault(def),
			composite.With(composite.Users, users),
		)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if s.AuthnLockouts() != users.AuthnLockouts() {
			t.Fatal("AuthnLockouts must follow the Users route, not the default")
		}
	})

	t.Run("users backend without the method", func(t *testing.T) {
		t.Parallel()
		s, err := composite.New(
			composite.WithDefault(newInmem(t)),
			composite.With(composite.Users, newReadOnlyStore(t)),
		)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if got := s.AuthnLockouts(); got != nil {
			t.Fatalf("AuthnLockouts must be nil when the Users backend lacks the method, got %T", got)
		}
	})
}
