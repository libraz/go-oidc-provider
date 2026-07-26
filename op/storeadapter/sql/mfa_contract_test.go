package oidcsql_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/store/contract"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// seedContractUser adapts the adapter's own directory writer to the
// harness's seeding hook. The library never enrols a user, so this is
// test-only wiring rather than a production path.
func seedContractUser(s *oidcsql.Store) func(*testing.T, *store.User, string, []byte) {
	return func(t *testing.T, u *store.User, username string, passwordHash []byte) {
		t.Helper()
		if err := s.PutUserWithPassword(t.Context(), u, username, passwordHash); err != nil {
			t.Fatalf("PutUserWithPassword: %v", err)
		}
	}
}

// runMFAContracts drives every authentication-factor contract against
// the adapter the factory produces. Those substores are deliberately
// absent from [store.Store] — the login flow receives them directly —
// so the helper reaches them through the concrete adapter type rather
// than through [contract.Backend.Store].
//
// Each dialect's contract test calls this alongside [contract.Run] so
// the factor tables are exercised on the same engine and in the same
// container as the rest of the suite.
func runMFAContracts(t *testing.T, f contract.Factory) {
	t.Helper()

	adapter := func(t *testing.T) *oidcsql.Store {
		t.Helper()
		b := f(t)
		s, ok := b.Store.(*oidcsql.Store)
		if !ok {
			t.Fatalf("factory produced %T, want *oidcsql.Store", b.Store)
		}
		return s
	}

	t.Run("TOTPStore", func(t *testing.T) {
		t.Parallel()
		contract.RunTOTPs(t, func(t *testing.T) store.TOTPStore {
			t.Helper()
			return adapter(t).TOTPs()
		})
	})

	t.Run("RecoveryStore", func(t *testing.T) {
		t.Parallel()
		contract.RunRecoveryCodes(t, func(t *testing.T) store.RecoveryStore {
			t.Helper()
			return adapter(t).RecoveryCodes()
		})
	})

	t.Run("PasskeyStore", func(t *testing.T) {
		t.Parallel()
		contract.RunPasskeys(t, func(t *testing.T) store.PasskeyStore {
			t.Helper()
			return adapter(t).Passkeys()
		})
	})

	t.Run("AuthnLockoutStore", func(t *testing.T) {
		t.Parallel()
		contract.RunAuthnLockouts(t, func(t *testing.T) store.AuthnLockoutStore {
			t.Helper()
			return adapter(t).AuthnLockouts()
		})
	})

	t.Run("EmailOTPStore", func(t *testing.T) {
		t.Parallel()
		contract.RunEmailOTPs(t, func(t *testing.T) contract.EmailOTPBackend {
			t.Helper()
			b := f(t)
			s, ok := b.Store.(*oidcsql.Store)
			if !ok {
				t.Fatalf("factory produced %T, want *oidcsql.Store", b.Store)
			}
			return contract.EmailOTPBackend{Store: s.EmailOTPs(), Now: b.Now}
		})
	})
}
