package oidcredis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// sessionStore implements [store.SessionStore] against Redis. Records
// are JSON-encoded under a per-id key with native TTL derived from
// [store.Session.ExpiresAt]. The chooser-group lookup is backed by a
// per-group SET that mirrors the parent record's lifecycle: Save
// adds the session ID to the set, Delete removes it, and
// ListByChooserGroup performs lazy cleanup of stale IDs whose parent
// record has been evicted by Redis TTL.
//
// SessionStore lives outside the transactional cluster: the OP does
// not coordinate Session writes with token-endpoint
// commits, so the adapter does not implement a tx-bound variant.
// Embedders pair this implementation with a transactional backend
// for the rest of the catalogue via op/storeadapter/composite.
type sessionStore struct {
	parent *Store
}

func newSessionStore(parent *Store) *sessionStore {
	return &sessionStore{parent: parent}
}

// sessionRecord is the on-the-wire shape Save / Find round-trip. The
// short field tags keep the serialised payload well under
// [MaxValueBytes] for typical drivers; the chooser-group identifier
// rides with the record so Find can return a complete [store.Session]
// without consulting the secondary index.
type sessionRecord struct {
	ID             string    `json:"id"`
	Subject        string    `json:"sub"`
	AuthTime       time.Time `json:"at"`
	AMR            []string  `json:"amr,omitempty"`
	ACR            string    `json:"acr,omitempty"`
	ChooserGroupID string    `json:"cg"`
	ExpiresAt      time.Time `json:"exp"`
	CreatedAt      time.Time `json:"cat"`
	UpdatedAt      time.Time `json:"uat"`
}

func (s *sessionStore) sessionKey(id string) string {
	return s.parent.prefix + "session:" + id
}

func (s *sessionStore) chooserGroupKey(groupID string) string {
	return s.parent.prefix + "session:cg:" + groupID
}

// Save persists a new session or replaces an existing one. The store
// contract permits upsert; the inmem reference also upserts and the
// implementation here is symmetric. When the supplied session
// changes the ChooserGroupID of an existing record, the secondary
// index is updated atomically: the ID is removed from the previous
// group's SET before it is added to the new one. The parent record
// SET and the index SADD are issued through a Redis pipeline so a
// single round-trip keeps Save proportional to the network latency
// of one command.
func (s *sessionStore) Save(ctx context.Context, sess *store.Session) error {
	if sess == nil {
		return errors.New("oidcredis: nil session")
	}
	payload, err := s.encode(sess)
	if err != nil {
		return err
	}
	if len(payload) > s.parent.maxValueBytes {
		return fmt.Errorf("oidcredis: session payload %d bytes exceeds %d-byte cap",
			len(payload), s.parent.maxValueBytes)
	}
	ttl := sess.ExpiresAt.Sub(s.parent.clock.Now())
	if ttl <= 0 {
		// Past-dated Save: drop. The contract permits backends to
		// treat already-expired records as absent on read, so writing
		// one would only manufacture a Find/ListByChooserGroup hit
		// that the expiry filter immediately rejects.
		return nil
	}

	// Upsert path: if the record already exists with a different
	// chooser group, evict the stale secondary-index entry before
	// recording the new one. This is best-effort — a concurrent Save
	// against the same ID is undefined per the contract.
	if existing, err := s.fetch(ctx, sess.ID); err == nil &&
		existing != nil && existing.ChooserGroupID != "" &&
		existing.ChooserGroupID != sess.ChooserGroupID {
		_ = s.parent.client.SRem(ctx, s.chooserGroupKey(existing.ChooserGroupID), sess.ID).Err()
	}

	pipe := s.parent.client.TxPipeline()
	pipe.Set(ctx, s.sessionKey(sess.ID), payload, ttl)
	if sess.ChooserGroupID != "" {
		pipe.SAdd(ctx, s.chooserGroupKey(sess.ChooserGroupID), sess.ID)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("oidcredis: SET session: %w", err)
	}
	return nil
}

// Find returns the session identified by id, or [store.ErrNotFound]
// when no such session exists. Redis evicts expired keys lazily, so
// a Find against an expired ID returns ErrNotFound automatically.
// The defence-in-depth re-check against the adapter clock mirrors
// [interactionStore.Find] and protects against clock skew between the
// adapter and the Redis server.
func (s *sessionStore) Find(ctx context.Context, id string) (*store.Session, error) {
	rec, err := s.fetch(ctx, id)
	if err != nil {
		return nil, err
	}
	if patterns.IsExpiredInclusive(rec.ExpiresAt, s.parent.clock.Now()) {
		return nil, store.ErrNotFound
	}
	return decode(rec), nil
}

// Touch extends the session's idle timer without recreating a deleted
// record. Redis has no compare-and-update JSON primitive in the plain
// command set, so the adapter fetches and rewrites the encoded value, then
// commits with SET XX. If a concurrent Delete removes the key between the
// fetch and the write, SET XX reports false and Touch returns ErrNotFound
// instead of resurrecting the session. The chooser-group set is not
// touched — Touch only changes the TTL and UpdatedAt fields on the parent
// record.
func (s *sessionStore) Touch(ctx context.Context, id string, expiresAt, updatedAt time.Time) error {
	rec, err := s.fetch(ctx, id)
	if err != nil {
		return err
	}
	if patterns.IsExpiredInclusive(rec.ExpiresAt, s.parent.clock.Now()) {
		return store.ErrNotFound
	}
	rec.ExpiresAt = expiresAt
	rec.UpdatedAt = updatedAt
	payload, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("oidcredis: marshal session: %w", err)
	}
	if len(payload) > s.parent.maxValueBytes {
		return fmt.Errorf("oidcredis: session payload %d bytes exceeds %d-byte cap",
			len(payload), s.parent.maxValueBytes)
	}
	ttl := expiresAt.Sub(s.parent.clock.Now())
	if ttl <= 0 {
		// Past-dated Touch: equivalent to Delete from the contract's
		// perspective (next Find returns ErrNotFound). We perform a
		// real Delete to keep the chooser-group index honest.
		return s.Delete(ctx, id)
	}
	ok, err := s.parent.client.SetXX(ctx, s.sessionKey(id), payload, ttl).Result()
	if err != nil {
		return fmt.Errorf("oidcredis: SET session (Touch): %w", err)
	}
	if !ok {
		return store.ErrNotFound
	}
	return nil
}

// Delete removes the session identified by id. The chooser-group
// index entry is removed in the same pipeline; lazy cleanup in
// [sessionStore.ListByChooserGroup] handles the case where Redis
// TTL beat us to the parent record.
func (s *sessionStore) Delete(ctx context.Context, id string) error {
	rec, fetchErr := s.fetch(ctx, id)
	if errors.Is(fetchErr, store.ErrNotFound) {
		return store.ErrNotFound
	}
	if fetchErr != nil {
		return fetchErr
	}

	pipe := s.parent.client.TxPipeline()
	delCmd := pipe.Del(ctx, s.sessionKey(id))
	if rec.ChooserGroupID != "" {
		pipe.SRem(ctx, s.chooserGroupKey(rec.ChooserGroupID), id)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("oidcredis: DEL session: %w", err)
	}
	if delCmd.Val() == 0 {
		return store.ErrNotFound
	}
	return nil
}

// ListByChooserGroup returns every non-expired session whose
// ChooserGroupID matches groupID. The lookup is two-phase:
// SMEMBERS yields the candidate IDs, then a single MGET fetches the
// payloads. Stale IDs whose parent record has been TTL-evicted are
// removed from the index opportunistically (lazy cleanup), so the
// secondary index does not unbounded-grow against churning sessions.
func (s *sessionStore) ListByChooserGroup(ctx context.Context, groupID string) ([]*store.Session, error) {
	ids, err := s.parent.client.SMembers(ctx, s.chooserGroupKey(groupID)).Result()
	if err != nil {
		return nil, fmt.Errorf("oidcredis: SMEMBERS chooser group: %w", err)
	}
	if len(ids) == 0 {
		return []*store.Session{}, nil
	}
	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = s.sessionKey(id)
	}
	rawValues, err := s.parent.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("oidcredis: MGET sessions: %w", err)
	}

	out, stale := s.partitionLiveAndStale(ids, rawValues)
	if len(stale) > 0 {
		// Best-effort cleanup; the secondary index is a hint, not a
		// source of truth, so a partial SREM failure is non-fatal.
		toRemove := make([]any, len(stale))
		for i, id := range stale {
			toRemove[i] = id
		}
		_ = s.parent.client.SRem(ctx, s.chooserGroupKey(groupID), toRemove...).Err()
	}
	return out, nil
}

// partitionLiveAndStale splits the parallel ids / rawValues slices into
// (live sessions, IDs whose parent record is missing or unparseable
// or already expired). The classification is collapsed into a single
// helper so [sessionStore.ListByChooserGroup] reads as a flat
// "fetch → partition → cleanup" pipeline rather than a nested loop.
func (s *sessionStore) partitionLiveAndStale(
	ids []string,
	rawValues []any,
) ([]*store.Session, []string) {
	out := make([]*store.Session, 0, len(rawValues))
	stale := make([]string, 0)
	now := s.parent.clock.Now()
	for i, raw := range rawValues {
		rec, ok := decodeSessionRaw(raw)
		if !ok || patterns.IsExpiredInclusive(rec.ExpiresAt, now) {
			stale = append(stale, ids[i])
			continue
		}
		out = append(out, decode(rec))
	}
	return out, stale
}

// decodeSessionRaw unmarshals one MGET result into a [sessionRecord].
// A nil result, a non-string result, or an unparseable JSON payload
// all collapse to "(nil, false)" so the caller treats them uniformly
// as stale entries; the caller is responsible for the expiry check
// because it depends on the adapter clock.
func decodeSessionRaw(raw any) (*sessionRecord, bool) {
	if raw == nil {
		return nil, false
	}
	payload, ok := raw.(string)
	if !ok {
		return nil, false
	}
	var rec sessionRecord
	if err := json.Unmarshal([]byte(payload), &rec); err != nil {
		return nil, false
	}
	return &rec, true
}

// fetch returns the on-the-wire record for id, or [store.ErrNotFound]
// when Redis reports the key as absent. Callers MUST re-check expiry
// against the adapter clock (defence in depth) before treating the
// record as live.
func (s *sessionStore) fetch(ctx context.Context, id string) (*sessionRecord, error) {
	raw, err := s.parent.client.Get(ctx, s.sessionKey(id)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, store.ErrNotFound
		}
		return nil, fmt.Errorf("oidcredis: GET session: %w", err)
	}
	var rec sessionRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		return nil, fmt.Errorf("oidcredis: unmarshal session: %w", err)
	}
	return &rec, nil
}

func (s *sessionStore) encode(sess *store.Session) ([]byte, error) {
	payload, err := json.Marshal(sessionRecord{
		ID:             sess.ID,
		Subject:        sess.Subject,
		AuthTime:       sess.AuthTime,
		AMR:            slices.Clone(sess.AMR),
		ACR:            sess.ACR,
		ChooserGroupID: sess.ChooserGroupID,
		ExpiresAt:      sess.ExpiresAt,
		CreatedAt:      sess.CreatedAt,
		UpdatedAt:      sess.UpdatedAt,
	})
	if err != nil {
		return nil, fmt.Errorf("oidcredis: marshal session: %w", err)
	}
	return payload, nil
}

func decode(rec *sessionRecord) *store.Session {
	return &store.Session{
		ID:             rec.ID,
		Subject:        rec.Subject,
		AuthTime:       rec.AuthTime,
		AMR:            slices.Clone(rec.AMR),
		ACR:            rec.ACR,
		ChooserGroupID: rec.ChooserGroupID,
		ExpiresAt:      rec.ExpiresAt,
		CreatedAt:      rec.CreatedAt,
		UpdatedAt:      rec.UpdatedAt,
	}
}
