//go:build example

// op.go — OP-side wiring for example 26-byo-store-from-scratch.
//
// buildProvider passes the hand-rolled scratchStore straight to
// op.WithStore. Because scratchStore.GrantRevocations() returns nil,
// the build pins op.WithAccessTokenRevocationStrategy(RevocationStrategyNone)
// so the library accepts the missing substore. The PrimaryPassword
// login Step reads credentials through the same scratchStore's Users()
// substore (store.UserPasswordStore).
//
// The store implements only the read-only store.ClientStore (GetClient),
// not store.ClientRegistry, so WithStaticClients is intentionally NOT
// used: it requires a writable registry. Instead seedClient inserts the
// demo client row into vault_relying_parties at boot, and the OP
// resolves it through GetClient on every request like any other store.

package main

import (
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
)

func buildProvider(storage *scratchStore) (*op.Provider, error) {
	keys := devkeys.MustEphemeral("byo-store-from-scratch-1")

	// The login Step needs the password lookups, so reach the concrete
	// user substore as a store.UserPasswordStore.
	users, ok := storage.Users().(store.UserPasswordStore)
	if !ok {
		return nil, errors.New("scratch users substore does not implement store.UserPasswordStore")
	}

	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: users},
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(storage),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithLoginFlow(flow),
		// GrantRevocations() is nil, so the OP cannot persist JWT
		// revocation tombstones. Disable server-side JWT revocation so
		// op.New accepts the missing substore (fail-fast otherwise).
		op.WithAccessTokenRevocationStrategy(op.RevocationStrategyNone),
	)
	if err != nil {
		return nil, fmt.Errorf("op.New: %w", err)
	}
	return provider, nil
}
