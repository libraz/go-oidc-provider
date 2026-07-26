package oidcdynamo

import (
	"context"
	"errors"

	"github.com/libraz/go-oidc-provider/op/store"
)

// metadataStore is the SQL-free key/value corner of the adapter: it
// holds OP-internal state that is neither user data nor token material,
// currently the subject_mode marker the pairwise immutability gate
// reads at construction time.
type metadataStore struct {
	parent *Store
}

func (s *metadataStore) Get(ctx context.Context, key string) (string, error) {
	found, err := s.parent.get(ctx, s.parent.names.metadata, key)
	if errors.Is(err, store.ErrNotFound) {
		return "", store.ErrNotFound
	}
	if err != nil {
		return "", wrapErr("metadata.Get", err)
	}
	return readS(found, attrValue), nil
}

func (s *metadataStore) Set(ctx context.Context, key, value string) error {
	i := newItem(key)
	i[attrValue] = avS(value)
	if err := s.parent.put(ctx, s.parent.names.metadata, i); err != nil {
		return wrapErr("metadata.Set", err)
	}
	return nil
}

var _ store.MetadataStore = (*metadataStore)(nil)
