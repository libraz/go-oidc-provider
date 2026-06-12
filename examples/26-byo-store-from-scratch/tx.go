//go:build example

// tx.go — store.Transactional support. BeginTx opens one *sql.Tx and
// returns a store.Tx whose substore accessors are all bound to it. The OP
// runtime does not require this extension, but it is useful for embedders
// that perform their own maintenance or migration writes.
//
// store.Tx exposes only AuthorizationCodes / Grants / RefreshTokens /
// PushedAuthRequests / Commit / Rollback. AccessTokens() is exported here as
// an optional convenience for callers that hold the concrete *scratchTx; it is
// not part of the public store.Tx contract.

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

// AccessTokens returns the tx-bound registry. store.Tx does not declare this
// method; it is available only to callers that hold the concrete *scratchTx.
func (t *scratchTx) AccessTokens() store.AccessTokenRegistry {
	return &accessTokenStore{q: t.tx}
}

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
