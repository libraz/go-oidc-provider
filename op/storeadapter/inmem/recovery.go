package inmem

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/libraz/go-oidc-provider/op/store"
)

// recoveryStore is the in-memory reference implementation of
// [store.RecoveryStore]. It mirrors the read/write contract used by the
// other inmem substores: every Get clones the batch so callers may
// mutate the slot list freely, and every Put clones the supplied
// pointer so a later mutation by the caller does not leak into the map.
type recoveryStore struct {
	mu sync.RWMutex
	m  map[string]*store.RecoveryBatch
}

func newRecoveryStore() *recoveryStore {
	return &recoveryStore{m: make(map[string]*store.RecoveryBatch)}
}

// Get implements [store.RecoveryStore].
func (s *recoveryStore) Get(_ context.Context, subject string) (*store.RecoveryBatch, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.m[subject]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneRecoveryBatch(b), nil
}

// Put implements [store.RecoveryStore]. The reference implementation has
// upsert semantics: a batch at the same Subject is overwritten in
// place, matching the contract documented on the interface (regenerating
// a fresh batch replaces the previous one wholesale).
func (s *recoveryStore) Put(_ context.Context, b *store.RecoveryBatch) error {
	if b == nil {
		return errors.New("inmem: nil recovery batch")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[b.Subject] = cloneRecoveryBatch(b)
	return nil
}

// Consume implements [store.RecoveryStore].
func (s *recoveryStore) Consume(_ context.Context, b *store.RecoveryBatch, index int) error {
	if b == nil {
		return errors.New("inmem: nil recovery batch")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.m[b.Subject]
	if !ok {
		return store.ErrNotFound
	}
	if index < 0 || index >= len(current.Codes) || index >= len(b.Codes) {
		return store.ErrNotFound
	}
	// The batch may have been regenerated between the caller's Get and
	// this Consume. A hash mismatch means the presented code belongs to a
	// superseded batch and MUST NOT redeem a slot of the current one —
	// otherwise a code the user revoked by regenerating could still burn
	// a fresh slot (revocation bypass). Mirrors emailOTPStore.Consume.
	if current.Codes[index].Hash != b.Codes[index].Hash {
		return store.ErrAlreadyConsumed
	}
	if !current.Codes[index].ConsumedAt.IsZero() {
		return store.ErrAlreadyConsumed
	}
	next := cloneRecoveryBatch(current)
	next.Codes[index].ConsumedAt = b.Codes[index].ConsumedAt
	s.m[b.Subject] = next
	return nil
}

// Delete implements [store.RecoveryStore].
func (s *recoveryStore) Delete(_ context.Context, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[subject]; !ok {
		return store.ErrNotFound
	}
	delete(s.m, subject)
	return nil
}

func cloneRecoveryBatch(b *store.RecoveryBatch) *store.RecoveryBatch {
	if b == nil {
		return nil
	}
	out := *b
	out.Codes = slices.Clone(b.Codes)
	return &out
}
