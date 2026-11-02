package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

// execer is the write half of [runner]; a *databasesql.DB satisfies it
// as well, for the substores that never join a transaction.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (databasesql.Result, error)
}

// execCount runs a write and returns the number of rows it affected.
// The affected-row failure is reported under op+".RowsAffected".
func execCount(ctx context.Context, e execer, op, query string, args ...any) (int64, error) {
	res, err := e.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, wrapErr(op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, wrapErr(op+".RowsAffected", err)
	}
	return n, nil
}

// execDeleteOne runs a DELETE and reports [store.ErrNotFound] when it
// removed no row.
func execDeleteOne(ctx context.Context, e execer, op, query string, args ...any) error {
	n, err := execCount(ctx, e, op, query, args...)
	if err != nil {
		return err
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}

// deleteLive deletes the row keyed by id but reports [store.ErrNotFound]
// when the record was already expired. The DELETE alone cannot tell a
// live row from an expired one awaiting collection, so find (the
// substore's expiry-aware lookup) runs first; the row is reclaimed
// either way.
func deleteLive(ctx context.Context, e execer, op, query, id string, find func() error) error {
	findErr := find()
	absent := errors.Is(findErr, store.ErrNotFound)
	if findErr != nil && !absent {
		return findErr
	}
	if err := execDeleteOne(ctx, e, op, query, id); err != nil {
		return err
	}
	if absent {
		return store.ErrNotFound
	}
	return nil
}
