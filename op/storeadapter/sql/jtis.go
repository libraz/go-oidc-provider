package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

type jtiStore struct {
	parent *Store
	tx     *databasesql.Tx
}

func newJTIStore(s *Store, tx *databasesql.Tx) *jtiStore {
	return &jtiStore{parent: s, tx: tx}
}

func (s *jtiStore) runner() runner { return pickRunner(s.parent, s.tx) }

// Mark records jti as consumed. The raw jti is hashed via
// [patterns.Digest] before binding to SQL so the bearer-leakage
// surface (driver logs, replication snapshots, EXPLAIN traces) only
// ever sees the SHA-256 digest. JWT IDs may legitimately be long
// (RFC 7519 sets no upper bound); hashing also bounds the persisted
// length to a fixed 64-char hex value.
func (s *jtiStore) Mark(ctx context.Context, jti string, expiresAt time.Time) error {
	digest := patterns.Digest(jti)
	now := s.parent.clock.Now()
	if _, err := s.runner().ExecContext(ctx, s.parent.queries.jtiDeleteExpired, digest, timeToInt64(now)); err != nil {
		return wrapErr("jtis.Mark.deleteExpired", err)
	}
	_, err := s.runner().ExecContext(ctx, s.parent.queries.jtiMark, digest, timeToInt64(expiresAt))
	if err != nil {
		if isDuplicate(err) {
			return store.ErrAlreadyConsumed
		}
		return wrapErr("jtis.Mark", err)
	}
	return nil
}

// Has reports whether jti has previously been marked. The raw jti is
// hashed via [patterns.Digest] before the WHERE lookup so the same
// bearer-leakage posture as [jtiStore.Mark] applies.
func (s *jtiStore) Has(ctx context.Context, jti string) (bool, error) {
	digest := patterns.Digest(jti)
	var exp int64
	err := s.runner().QueryRowContext(ctx, s.parent.queries.jtiHas, digest).Scan(&exp)
	if errors.Is(err, databasesql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, wrapErr("jtis.Has", err)
	}
	if exp != 0 && s.parent.clock.Now().UnixNano() >= exp {
		// Treat expired entries as absent so stale evictions surface
		// to the caller; the contract permits this shape.
		return false, nil
	}
	return true, nil
}

// GC drops every row whose expires_at is strictly before cutoff.
// Embedders typically run GC from a periodic sweeper; the helper is
// exported on the concrete type so they can reach it via *Store.
func (s *jtiStore) GC(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.runner().ExecContext(ctx, s.parent.queries.jtiGC, timeToInt64(cutoff))
	if err != nil {
		return 0, wrapErr("jtis.GC", err)
	}
	return res.RowsAffected()
}
