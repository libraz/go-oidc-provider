package oidcredis

import (
	"context"
	"errors"
	"fmt"

	"github.com/redis/go-redis/v9"

	"github.com/libraz/go-oidc-provider/op/store"
)

// metadataStore implements [store.MetadataStore] against a Redis hash.
// The substore is the persistence path for coarse construction-time
// decisions (subject_mode in v0.9.1); future keys land on the same
// surface without further interface change.
//
// Storage shape: every key/value lives in a single Redis hash so
// `HGETALL <prefix>op_metadata` returns the entire fact set in one
// round-trip. The hash's keyspace is tiny (single-digit entries
// expected) so HSET / HGET dominate; hashes also avoid the per-key
// EXPIRE overhead the adapter reserves for transient records.
type metadataStore struct {
	parent *Store
}

func newMetadataStore(parent *Store) *metadataStore { return &metadataStore{parent: parent} }

// hashKey returns the Redis hash key the substore lives under. The
// hash holds every metadata entry so `Get` / `Set` resolve to a single
// HGET / HSET each.
func (m *metadataStore) hashKey() string { return m.parent.prefix + "op_metadata" }

func (m *metadataStore) Get(ctx context.Context, key string) (string, error) {
	val, err := m.parent.client.HGet(ctx, m.hashKey(), key).Result()
	if errors.Is(err, redis.Nil) {
		return "", store.ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("oidcredis: HGET op_metadata: %w", err)
	}
	return val, nil
}

func (m *metadataStore) Set(ctx context.Context, key, value string) error {
	if err := m.parent.client.HSet(ctx, m.hashKey(), key, value).Err(); err != nil {
		return fmt.Errorf("oidcredis: HSET op_metadata: %w", err)
	}
	return nil
}
