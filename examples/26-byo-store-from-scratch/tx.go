//go:build example

// tx.go — store.Transactional support. BeginTx opens one *sql.Tx and
// returns a store.Tx whose substore accessors are all bound to it. The OP
// runtime does not require this extension, but it is useful for embedders
// that perform their own maintenance or migration writes.
//
// store.Tx exposes AuthorizationCodes, Grants, RefreshTokens,
// PushedAuthRequests, AccessTokens, OpaqueAccessTokens, and
// GrantRevocations, plus Commit / Rollback. This minimal example does not
// implement opaque access tokens or grant-revocation tombstones, so those two
// transaction accessors return nil just like their parent-store accessors.

package main

import (
	"context"
	databasesql "database/sql"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/op/store"
)

// BeginTx implements store.Transactional. Every substore the returned
// Tx hands out is bound to the single underlying *sql.Tx.
func (s *scratchStore) BeginTx(ctx context.Context) (store.Tx, error) {
	dbtx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("scratch: begin transaction: %w", err)
	}
	return &scratchTx{parent: s, tx: dbtx}, nil
}

type scratchTx struct {
	parent *scratchStore
	tx     *databasesql.Tx
	done   bool
}

func (t *scratchTx) AuthorizationCodes() store.AuthorizationCodeStore {
	return &authCodeStore{q: t.tx, now: t.parent.now}
}

func (t *scratchTx) Grants() store.GrantStore {
	return &grantStore{q: t.tx, now: t.parent.now}
}

func (t *scratchTx) RefreshTokens() store.RefreshTokenStore {
	return &refreshStore{q: t.tx, now: t.parent.now}
}

func (t *scratchTx) PushedAuthRequests() store.PushedAuthRequestStore {
	return &parStore{q: t.tx, now: t.parent.now}
}

// AccessTokens returns the tx-bound registry.
func (t *scratchTx) AccessTokens() store.AccessTokenRegistry {
	return &accessTokenStore{q: t.tx}
}

// OpaqueAccessTokens returns nil because this minimal store does not support
// opaque access tokens. A complete adapter returns its tx-bound substore here.
func (t *scratchTx) OpaqueAccessTokens() store.OpaqueAccessTokenStore { return nil }

// GrantRevocations returns nil because this minimal store does not persist
// JWT grant tombstones. A complete adapter returns its tx-bound substore here.
func (t *scratchTx) GrantRevocations() store.GrantRevocationStore { return nil }

func (t *scratchTx) Commit() error {
	if t.done {
		return store.ErrTxRequired
	}
	t.done = true
	if err := t.tx.Commit(); err != nil {
		return fmt.Errorf("scratch: commit transaction: %w", err)
	}
	return nil
}

func (t *scratchTx) Rollback() error {
	if t.done {
		return nil
	}
	t.done = true
	if err := t.tx.Rollback(); err != nil && !errors.Is(err, databasesql.ErrTxDone) {
		return fmt.Errorf("scratch: rollback transaction: %w", err)
	}
	return nil
}

var _ store.Tx = (*scratchTx)(nil)
