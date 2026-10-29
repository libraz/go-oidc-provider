//go:build example

package main

import (
	"context"
	"fmt"
	"log"

	"github.com/libraz/go-oidc-provider/op"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"
)

// staticClients is the client list the Provider is built with. Start-up
// inserts a missing client but refuses one whose stored record differs,
// so an edit here (a new redirect URI, a rotated secret) is applied with
// the sync-clients command first.
//
// The literal secret is for the demo. Production seeds SecretHash with
// the hash printed by
// "go run github.com/libraz/go-oidc-provider/cmd/op-client-secret", or
// reads Secret from its secret store.
func staticClients() []op.ClientSeed {
	return []op.ClientSeed{
		op.ConfidentialClient{
			ID:           "production-sql-rp",
			Secret:       "production-sql-demo-secret-rotate-me",
			AuthMethod:   op.AuthClientSecretBasic,
			RedirectURIs: []string{"http://127.0.0.1:8081/callback"},
			Scopes:       []string{"openid", "profile", "email"},
		},
	}
}

// syncClients writes staticClients to the store and exits. Run it from a
// deploy job before the new version starts. It never deletes a client
// and refuses to touch one that was registered dynamically.
func syncClients(ctx context.Context, storage *oidcsql.Store) error {
	results, err := op.SyncStaticClients(ctx, storage, staticClients()...)
	for _, r := range results {
		log.Printf("client %s: %s", r.ID, r.Action)
	}
	if err != nil {
		return fmt.Errorf("sync clients: %w", err)
	}
	return nil
}
