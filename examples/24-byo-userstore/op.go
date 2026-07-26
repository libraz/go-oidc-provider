//go:build example

// op.go — OP-side wiring for example 24-byo-userstore.
//
// buildProvider composes the OP's record store from two halves: the
// bundled op/storeadapter/sql.Store covers every OIDC table (clients,
// codes, refresh tokens, grants, sessions, PAR, IATs, RATs, access
// tokens, JTIs, revocations) while MemberUserStore (in store.go)
// projects the embedder-owned members table onto store.UserStore.
//
// op.WithUserStore is what joins them. Nothing wraps the bundled store,
// so the transactional cluster (authorization-code exchange,
// refresh-token rotation, PAR consumption) keeps committing against the
// same SQLite database and every optional capability the adapter
// implements stays visible to op.New.
//
// The same MemberUserStore value is handed to PrimaryPassword, so the
// records a login authenticates against are the records the ID Token is
// built from. op.New warns when those two differ.

package main

import (
	"context"
	"fmt"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"

	databasesql "database/sql"
)

func buildProvider(ctx context.Context, db *databasesql.DB) (*op.Provider, error) {
	keys := devkeys.MustEphemeral("byo-userstore-1")

	durable, err := oidcsql.New(db, oidcsql.SQLite())
	if err != nil {
		return nil, fmt.Errorf("oidcsql.New: %w", err)
	}
	if err := durable.Migrate(ctx); err != nil {
		return nil, fmt.Errorf("migrate OIDC schema: %w", err)
	}

	members := &MemberUserStore{db: db}

	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: members},
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(durable),
		// Every OIDC record stays in the bundled schema; only the
		// end-user claims come from the members table.
		op.WithUserStore(members),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithLoginFlow(flow),
		op.WithStaticClients(op.PublicClient{
			ID:           clientID,
			RedirectURIs: []string{redirectURI},
			Scopes:       []string{"openid", "profile", "email"},
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("op.New: %w", err)
	}
	return provider, nil
}
