//go:build example

// op.go — OP-side wiring for example 24-byo-userstore.
//
// buildProvider composes the OP's record store from two halves: the
// bundled op/storeadapter/sql.Store covers every OIDC table (clients,
// codes, refresh tokens, grants, sessions, PAR, IATs, RATs, access
// tokens, JTIs, revocations) while MemberUserStore (in store.go)
// projects the embedder-owned members table onto store.UserStore.
// hybridStore stitches them together by embedding *oidcsql.Store and
// shadowing Users() with the MemberUserStore reference, so every
// OP call site that reads end-user claims reaches the embedder's
// schema while the transactional cluster (authorization-code
// exchange, refresh-token rotation, PAR consumption) keeps committing
// against the same SQLite database.

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

	// hybridStore is the value op.WithStore receives. The embedded
	// *oidcsql.Store provides every store.Store method except
	// Users(): that one is shadowed by the wrapper's own method, so
	// the OP's /userinfo and ID Token assembly reach MemberUserStore
	// at every call site that reads end-user claims.
	storage := &hybridStore{Store: durable, users: members}

	flow := op.LoginFlow{
		Primary: op.PrimaryPassword{Store: members},
	}

	provider, err := op.New(
		op.WithIssuer(issuer),
		op.WithStore(storage),
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
