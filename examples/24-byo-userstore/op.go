//go:build example

// op.go — OP-side wiring for example 24-byo-userstore.
//
// buildProvider composes the OP's record store from two halves: the
// bundled op/storeadapter/sql.Store covers every OIDC table (clients,
// codes, refresh tokens, grants, sessions, PAR, IATs, RATs, access
// tokens, JTIs, revocations) while MemberUserStore (in store.go)
// projects the embedder-owned members table onto store.UserStore.
//
// PrimaryPassword.Store is what joins them: with no op.WithUserStore,
// the OP reads ID Token and /userinfo claims from the store the password
// step authenticates against, so the login and the claims come from the
// same members rows. Nothing wraps the bundled store, so the
// transactional cluster (authorization-code exchange, refresh-token
// rotation, PAR consumption) keeps committing against the same SQLite
// database and every optional capability the adapter implements stays
// visible to op.New.

package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/profile"
	oidcsql "github.com/libraz/go-oidc-provider/op/storeadapter/sql"

	databasesql "database/sql"
)

func buildProvider(ctx context.Context, db *databasesql.DB) (*op.Provider, error) {
	keys := devkeys.MustEphemeral("byo-userstore-1")

	durable, err := oidcsql.New(db, oidcsql.SQLite())
	if err != nil {
		return nil, fmt.Errorf("oidcsql.New: %w", err)
	}
	// Migrate creates or upgrades the tables and records the schema version;
	// a migration tool applies Store.Migrations() instead.
	if err := durable.Migrate(ctx); err != nil {
		return nil, fmt.Errorf("migrate OIDC schema: %w", err)
	}

	members := &MemberUserStore{db: db}

	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: members},
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		// Logs the claim source at start-up and any standard claim
		// dropped for having the wrong JSON type.
		op.WithLogger(slog.Default()),
		// Every OIDC record stays in the bundled schema; the end-user
		// claims come from the members table through the login flow.
		op.WithStore(durable),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithProfile(profile.OAuth21),
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
