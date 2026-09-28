package scenariokit

import (
	"context"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// SeedSubject puts subject into the provider's in-memory user store
// unless it is already there. The testkit seeds the subjects it logs in,
// but a device_code or CIBA approval written straight to the store
// bypasses the login, and the token endpoint refuses to redeem for a
// subject the user store cannot find.
func SeedSubject(tb testing.TB, p *testkit.Provider, subject string) {
	tb.Helper()
	if subject == "" {
		return
	}
	if _, err := p.Store.Users().FindBySubject(context.Background(), subject); err == nil {
		return
	}
	p.Store.PutUser(context.Background(), &store.User{Subject: subject})
}
