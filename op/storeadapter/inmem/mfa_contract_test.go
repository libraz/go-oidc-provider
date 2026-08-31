package inmem_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// The authentication-factor substores live outside the aggregate
// [store.Store], so each one is driven by its own contract entry point
// rather than by [contract.Run].

func TestTOTPStoreContract(t *testing.T) {
	t.Parallel()

	contract.RunTOTPs(t, func(*testing.T) contract.TOTPBackend {
		s := inmem.New()
		return contract.TOTPBackend{
			Store:   s.TOTPs(),
			Diverge: s.DivergeTOTPRecord,
		}
	})
}

func TestRecoveryStoreContract(t *testing.T) {
	t.Parallel()

	contract.RunRecoveryCodes(t, func(*testing.T) store.RecoveryStore {
		return inmem.New().RecoveryCodes()
	})
}

func TestEmailOTPStoreContract(t *testing.T) {
	t.Parallel()

	contract.RunEmailOTPs(t, func(t *testing.T) contract.EmailOTPBackend {
		t.Helper()
		clock := &mutableClock{now: contract.Reference}
		s := inmem.New(inmem.WithClock(clock))
		return contract.EmailOTPBackend{
			Store:   s.EmailOTPs(),
			Now:     clock.Now,
			Diverge: s.DivergeEmailOTPRecord,
		}
	})
}
