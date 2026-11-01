package inmem

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// --- InteractionStore --------------------------------------------------------

type interactionStore struct {
	mu           sync.RWMutex
	clock        Clock
	m            map[string]*store.Interaction
	savesSinceGC uint32
}

func newInteractionStore(c Clock) *interactionStore {
	return &interactionStore{clock: c, m: make(map[string]*store.Interaction)}
}

func (s *interactionStore) Save(_ context.Context, i *store.Interaction) error {
	if i == nil {
		return errors.New("inmem: nil interaction")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeGCLocked(s.clock.Now())
	s.m[i.ID] = cloneInteraction(i)
	return nil
}

// gcLocked drops every interaction whose ExpiresAt has passed. Find,
// CompareAndSwap, DeleteIfUnchanged, and the unconditional Delete all
// treat an expired interaction as absent and report ErrNotFound, so a
// swept row is indistinguishable from one that was left in place.
func (s *interactionStore) gcLocked(now time.Time) {
	for id, rec := range s.m {
		if patterns.IsExpiredStrict(rec.ExpiresAt, now) {
			delete(s.m, id)
		}
	}
	s.savesSinceGC = 0
}

func (s *interactionStore) maybeGCLocked(now time.Time) {
	s.savesSinceGC++
	if !sweepDue(s.savesSinceGC, fullGCInterval, len(s.m)) {
		return
	}
	s.gcLocked(now)
}

func (s *interactionStore) CompareAndSwap(
	_ context.Context,
	previous, next *store.Interaction,
) error {
	if previous == nil || next == nil || previous.ID == "" || previous.ID != next.ID {
		return errors.New("inmem: invalid interaction compare-and-swap")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.m[previous.ID]
	if !ok || isExpired(current.ExpiresAt, s.clock) {
		return store.ErrNotFound
	}
	if !store.InteractionStateEqual(previous, current) {
		return store.ErrConflict
	}
	s.m[next.ID] = cloneInteraction(next)
	return nil
}

func (s *interactionStore) DeleteIfUnchanged(
	_ context.Context,
	previous *store.Interaction,
) error {
	if previous == nil || previous.ID == "" {
		return errors.New("inmem: invalid conditional interaction delete")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.m[previous.ID]
	if !ok || isExpired(current.ExpiresAt, s.clock) {
		return store.ErrNotFound
	}
	if !store.InteractionStateEqual(previous, current) {
		return store.ErrConflict
	}
	delete(s.m, previous.ID)
	return nil
}

func (s *interactionStore) Find(_ context.Context, id string) (*store.Interaction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.m[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	return cloneInteraction(rec), nil
}

func (s *interactionStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[id]
	if !ok {
		return store.ErrNotFound
	}
	// Reclaim the entry either way, but report an expired record as
	// absent: the contract makes the answer turn on ExpiresAt, not on
	// whether the sweep has reached this key yet.
	delete(s.m, id)
	if isExpired(rec.ExpiresAt, s.clock) {
		return store.ErrNotFound
	}
	return nil
}

func cloneInteraction(i *store.Interaction) *store.Interaction {
	if i == nil {
		return nil
	}
	out := *i
	out.RawState = slices.Clone(i.RawState)
	return &out
}
