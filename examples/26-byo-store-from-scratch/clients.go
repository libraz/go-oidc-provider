//go:build example

// clients.go — store.ClientStore against vault_relying_parties.
//
// Only GetClient is implemented: the demo provisions its single client
// through seedClient at boot, so there is no dynamic registration path.

package main

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/op/store"
)

type clientStore struct{ q querier }

const clientSelect = `
SELECT relying_party, redirect_targets, permitted_scope, is_public
FROM vault_relying_parties WHERE relying_party = ?`

// GetClient implements store.ClientStore. It maps the
// vault_relying_parties row onto the small slice of store.Client fields
// the authorization-code flow needs.
func (s *clientStore) GetClient(ctx context.Context, id string) (*store.Client, error) {
	var (
		redirects string
		scopes    string
		isPublic  int64
	)
	c := &store.Client{ID: id, Source: store.ClientSourceStatic}
	err := s.q.QueryRowContext(ctx, clientSelect, id).Scan(&c.ID, &redirects, &scopes, &isPublic)
	if errors.Is(err, databasesql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("clients.GetClient: %w", err)
	}
	c.RedirectURIs = decodeStrings(redirects)
	c.Scopes = decodeStrings(scopes)
	c.PublicClient = isPublic == 1
	if c.PublicClient {
		c.TokenEndpointAuthMethod = "none"
	}
	c.GrantTypes = []string{"authorization_code", "refresh_token"}
	c.ResponseTypes = []string{"code"}
	return c, nil
}
