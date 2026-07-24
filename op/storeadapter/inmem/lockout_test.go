package inmem_test

import (
	"context"
	"errors"
	"math"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func TestAuthnLockoutStoreContract(t *testing.T) {
	t.Parallel()

	contract.RunAuthnLockouts(t, func(*testing.T) store.AuthnLockoutStore {
		return inmem.New().AuthnLockouts()
	})
}

func TestAuthnLockoutStoreRejectsInvalidTransition(t *testing.T) {
	t.Parallel()

	s := inmem.New().AuthnLockouts()
	ctx := context.Background()
	tests := []struct {
		name     string
		expected uint64
		next     *store.AuthnLockoutRecord
	}{
		{name: "nil record", next: nil},
		{name: "empty subject", next: &store.AuthnLockoutRecord{}},
		{
			name:     "version overflow",
			expected: math.MaxUint64,
			next:     &store.AuthnLockoutRecord{Subject: "alice"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			swapped, err := s.CompareAndSwap(ctx, tt.expected, tt.next)
			if err == nil {
				t.Fatal("CompareAndSwap error = nil, want validation error")
			}
			if swapped {
				t.Fatal("CompareAndSwap swapped invalid transition")
			}
		})
	}
}

func TestAuthnLockoutStoreHonorsCancelledContext(t *testing.T) {
	t.Parallel()

	s := inmem.New().AuthnLockouts()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Get(ctx, "alice"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get error = %v, want context.Canceled", err)
	}
	swapped, err := s.CompareAndSwap(ctx, 0, &store.AuthnLockoutRecord{Subject: "alice"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("CompareAndSwap error = %v, want context.Canceled", err)
	}
	if swapped {
		t.Fatal("CompareAndSwap swapped after cancellation")
	}
}
