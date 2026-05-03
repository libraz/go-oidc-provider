package oidcsql

import (
	"context"
	databasesql "database/sql"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

// metadataStore implements [store.MetadataStore] against the
// oidc_op_metadata key/value table. The substore exists so the OP can
// remember coarse construction-time decisions across process restarts
// without inventing new tables for one-off facts (subject_mode,
// generator fingerprint, schema version markers).
type metadataStore struct {
	parent *Store
	tx     *databasesql.Tx
}

func newMetadataStore(s *Store, tx *databasesql.Tx) *metadataStore {
	return &metadataStore{parent: s, tx: tx}
}

func (s *metadataStore) runner() runner { return pickRunner(s.parent, s.tx) }

func (s *metadataStore) Get(ctx context.Context, key string) (string, error) {
	var value string
	err := s.runner().QueryRowContext(ctx, s.parent.queries.metadataGet, key).Scan(&value)
	if errors.Is(err, databasesql.ErrNoRows) {
		return "", store.ErrNotFound
	}
	if err != nil {
		return "", wrapErr("metadata.Get", err)
	}
	return value, nil
}

func (s *metadataStore) Set(ctx context.Context, key, value string) error {
	if _, err := s.runner().ExecContext(ctx, s.parent.queries.metadataSet, key, value); err != nil {
		return wrapErr("metadata.Set", err)
	}
	return nil
}
