package op_test

import (
	"context"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestUserinfo_ClaimsFromPrimaryPasswordStore checks that without
// WithUserStore the claims come from the store the login flow
// authenticates against, not from the backend's Users(). Both stores hold
// the same subject with a different name, so only the value tells them
// apart.
func TestUserinfo_ClaimsFromPrimaryPasswordStore(t *testing.T) {
	t.Parallel()

	signKey := newTestKey(t, "userinfo-primary-store")
	backend := inmem.New()
	backend.PutUser(context.Background(), &store.User{
		Subject: "user-1",
		Claims:  map[string]any{"name": "Backend Name"},
	})
	primary := inmem.New()
	primary.PutUser(context.Background(), &store.User{
		Subject: "user-1",
		Claims:  map[string]any{"name": "Primary Name"},
	})

	provider, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(backend),
		op.WithKeyset(op.Keyset{signKey}),
		op.WithCookieKeys(newRandomCookieKey(t)),
		op.WithLoginFlow(op.LoginFlow{
			Primary: op.PrimaryPassword{Store: primary.UserPasswords()},
		}),
		userInfoTokenClient(),
	)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}

	if got := userInfoClaim(t, provider, signKey, "user-1", "name"); got != "Primary Name" {
		t.Fatalf("name=%v want the PrimaryPassword.Store value", got)
	}
}
