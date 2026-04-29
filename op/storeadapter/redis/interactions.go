package oidcredis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/libraz/go-oidc-provider/op/store"
)

// interactionStore implements [store.InteractionStore] against Redis.
// Records are JSON-encoded and stored under a per-id key with native
// TTL derived from Interaction.ExpiresAt. The key is namespaced under
// the configured prefix to keep the keyspace disjoint from other
// stores sharing the Redis instance.
type interactionStore struct {
	parent *Store
}

func newInteractionStore(parent *Store) *interactionStore {
	return &interactionStore{parent: parent}
}

// interactionRecord is the on-the-wire shape Save / Find round-trip.
// The exported field tags are short to keep the serialised payload
// well under [MaxValueBytes] for typical drivers.
type interactionRecord struct {
	ID        string    `json:"id"`
	ClientID  string    `json:"cid"`
	Step      string    `json:"step"`
	RawState  []byte    `json:"raw,omitempty"`
	ExpiresAt time.Time `json:"exp"`
	CreatedAt time.Time `json:"cat"`
	UpdatedAt time.Time `json:"uat"`
}

func (s *interactionStore) interactionKey(id string) string {
	return s.parent.prefix + "interaction:" + id
}

// Save persists a new interaction or replaces an existing one. The
// store interface explicitly permits upsert ("backends that perform
// upsert MAY treat Save as idempotent"); the inmem reference also
// upserts. Redis SET with TTL is a natural fit for the upsert model
// and keeps the implementation symmetrical with the inmem reference.
func (s *interactionStore) Save(ctx context.Context, i *store.Interaction) error {
	if i == nil {
		return errors.New("oidcredis: nil interaction")
	}
	payload, err := json.Marshal(interactionRecord{
		ID:        i.ID,
		ClientID:  i.ClientID,
		Step:      i.Step,
		RawState:  i.RawState,
		ExpiresAt: i.ExpiresAt,
		CreatedAt: i.CreatedAt,
		UpdatedAt: i.UpdatedAt,
	})
	if err != nil {
		return fmt.Errorf("oidcredis: marshal interaction: %w", err)
	}
	if len(payload) > s.parent.maxValueBytes {
		return fmt.Errorf("oidcredis: interaction payload %d bytes exceeds %d-byte cap",
			len(payload), s.parent.maxValueBytes)
	}
	ttl := i.ExpiresAt.Sub(s.parent.clock.Now())
	if ttl <= 0 {
		// The contract permits backends to drop expired records; an
		// already-expired Save is a no-op.
		return nil
	}
	if err := s.parent.client.Set(ctx, s.interactionKey(i.ID), payload, ttl).Err(); err != nil {
		return fmt.Errorf("oidcredis: SET interaction: %w", err)
	}
	return nil
}

// Find returns the interaction identified by id, or
// [store.ErrNotFound] when no such interaction exists. Redis evicts
// expired keys lazily, so a Find against an expired ID returns
// ErrNotFound automatically — the contract's "MUST NOT return expired
// interactions" clause is satisfied by the engine.
func (s *interactionStore) Find(ctx context.Context, id string) (*store.Interaction, error) {
	raw, err := s.parent.client.Get(ctx, s.interactionKey(id)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("oidcredis: GET interaction: %w", err)
	}
	var rec interactionRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("oidcredis: unmarshal interaction: %w", err)
	}
	// Defence in depth against clock skew between the adapter and the
	// Redis server: re-evaluate expiry against the adapter's clock.
	// In normal operation the Redis TTL has already evicted such
	// records and this branch is unreachable.
	if !rec.ExpiresAt.IsZero() && !rec.ExpiresAt.After(s.parent.clock.Now()) {
		return nil, store.ErrNotFound
	}
	return &store.Interaction{
		ID:        rec.ID,
		ClientID:  rec.ClientID,
		Step:      rec.Step,
		RawState:  rec.RawState,
		ExpiresAt: rec.ExpiresAt,
		CreatedAt: rec.CreatedAt,
		UpdatedAt: rec.UpdatedAt,
	}, nil
}

// Delete removes the interaction identified by id, returning
// [store.ErrNotFound] when no such record exists. Redis DEL returns
// the number of keys removed; zero indicates the contract's "MUST
// return ErrNotFound when no such interaction exists" condition.
func (s *interactionStore) Delete(ctx context.Context, id string) error {
	n, err := s.parent.client.Del(ctx, s.interactionKey(id)).Result()
	if err != nil {
		return fmt.Errorf("oidcredis: DEL interaction: %w", err)
	}
	if n == 0 {
		return store.ErrNotFound
	}
	return nil
}
