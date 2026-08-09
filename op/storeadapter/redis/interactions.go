package oidcredis

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
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

func (s *interactionStore) CompareAndSwap(
	ctx context.Context,
	previous, next *store.Interaction,
) error {
	if previous == nil || next == nil || previous.ID == "" || previous.ID != next.ID {
		return errors.New("oidcredis: invalid interaction compare-and-swap")
	}
	if patterns.IsExpiredInclusive(previous.ExpiresAt, s.parent.clock.Now()) {
		return store.ErrNotFound
	}
	replacement, err := marshalInteraction(next)
	if err != nil {
		return err
	}
	if len(replacement) > s.parent.maxValueBytes {
		return fmt.Errorf("oidcredis: interaction payload %d bytes exceeds %d-byte cap",
			len(replacement), s.parent.maxValueBytes)
	}
	ttl := next.ExpiresAt.Sub(s.parent.clock.Now())
	if ttl <= 0 {
		return store.ErrNotFound
	}
	const compareAndSwapInteraction = `
local current = redis.call("GET", KEYS[1])
if not current then return -1 end
local decoded = cjson.decode(current)
local raw = decoded["raw"] or ""
if decoded["id"] ~= ARGV[1] or raw ~= ARGV[2] then return 0 end
redis.call("SET", KEYS[1], ARGV[3], "PX", ARGV[4])
return 1
`
	ttlMilliseconds := int64((ttl + time.Millisecond - 1) / time.Millisecond)
	result, err := s.parent.client.Eval(
		ctx,
		compareAndSwapInteraction,
		[]string{s.interactionKey(previous.ID)},
		previous.ID,
		base64.StdEncoding.EncodeToString(previous.RawState),
		replacement,
		ttlMilliseconds,
	).Int()
	if err != nil {
		return fmt.Errorf("oidcredis: CAS interaction: %w", err)
	}
	switch result {
	case 1:
		return nil
	case -1:
		return store.ErrNotFound
	default:
		return store.ErrConflict
	}
}

func (s *interactionStore) DeleteIfUnchanged(
	ctx context.Context,
	previous *store.Interaction,
) error {
	if previous == nil || previous.ID == "" {
		return errors.New("oidcredis: invalid conditional interaction delete")
	}
	if patterns.IsExpiredInclusive(previous.ExpiresAt, s.parent.clock.Now()) {
		return store.ErrNotFound
	}
	const deleteInteractionIfUnchanged = `
local current = redis.call("GET", KEYS[1])
if not current then return -1 end
local decoded = cjson.decode(current)
local raw = decoded["raw"] or ""
if decoded["id"] ~= ARGV[1] or raw ~= ARGV[2] then return 0 end
redis.call("DEL", KEYS[1])
return 1
`
	result, err := s.parent.client.Eval(
		ctx,
		deleteInteractionIfUnchanged,
		[]string{s.interactionKey(previous.ID)},
		previous.ID,
		base64.StdEncoding.EncodeToString(previous.RawState),
	).Int()
	if err != nil {
		return fmt.Errorf("oidcredis: conditional DEL interaction: %w", err)
	}
	switch result {
	case 1:
		return nil
	case -1:
		return store.ErrNotFound
	default:
		return store.ErrConflict
	}
}

func marshalInteraction(i *store.Interaction) ([]byte, error) {
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
		return nil, fmt.Errorf("oidcredis: marshal interaction: %w", err)
	}
	return payload, nil
}

// Find returns the interaction identified by id, or
// [store.ErrNotFound] when no such interaction exists. Redis evicts
// expired keys lazily, so a Find against an expired ID returns
// ErrNotFound automatically — the contract's "MUST NOT return expired
// interactions" clause is satisfied by the engine.
func (s *interactionStore) Find(ctx context.Context, id string) (*store.Interaction, error) {
	rec, err := s.fetch(ctx, id)
	if err != nil {
		return nil, err
	}
	if s.expired(rec) {
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

// fetch returns the on-the-wire record for id, or [store.ErrNotFound]
// when Redis reports the key as absent. Callers MUST re-check expiry
// with [interactionStore.expired] before treating the record as live.
func (s *interactionStore) fetch(ctx context.Context, id string) (*interactionRecord, error) {
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
	return &rec, nil
}

// expired is defence in depth against clock skew between the adapter
// and the Redis server: it re-evaluates the record's own ExpiresAt
// against the adapter's clock. In normal operation the Redis TTL has
// already evicted such records and it never reports true.
func (s *interactionStore) expired(rec *interactionRecord) bool {
	return patterns.IsExpiredInclusive(rec.ExpiresAt, s.parent.clock.Now())
}

// Delete removes the interaction identified by id, returning
// [store.ErrNotFound] when no such record exists or when the record has
// expired. Reading before the DEL is what separates the two: DEL alone
// counts keys, and a record still resident but expired per the adapter
// clock must read as absent here exactly as it does through Find. The
// key is reclaimed either way.
func (s *interactionStore) Delete(ctx context.Context, id string) error {
	rec, err := s.fetch(ctx, id)
	if err != nil {
		return err
	}
	expired := s.expired(rec)
	n, err := s.parent.client.Del(ctx, s.interactionKey(id)).Result()
	if err != nil {
		return fmt.Errorf("oidcredis: DEL interaction: %w", err)
	}
	if n == 0 || expired {
		return store.ErrNotFound
	}
	return nil
}
