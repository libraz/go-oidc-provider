package inmem

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// --- SessionStore ------------------------------------------------------------

type sessionStore struct {
	mu           sync.RWMutex
	clock        Clock
	m            map[string]*store.Session
	savesSinceGC uint32
}

// sessionFullGCSaveInterval is how many Save calls pass between full
// sweeps of the session map. Every unauthenticated login attempt that
// reaches the session step can create a row, so the map needs
// reclamation; sweeping on each Save would make every login cost
// O(total sessions).
const sessionFullGCSaveInterval uint32 = 64

func newSessionStore(c Clock) *sessionStore {
	return &sessionStore{clock: c, m: make(map[string]*store.Session)}
}

func (s *sessionStore) Save(_ context.Context, sess *store.Session) error {
	if sess == nil {
		return errors.New("inmem: nil session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeGCLocked(s.clock.Now())
	s.m[sess.ID] = cloneSession(sess)
	return nil
}

// gcLocked drops every session whose ExpiresAt has passed. Find, Touch,
// ListByChooserGroup, and Delete all treat an expired session as
// absent, so removing it cannot change what a caller observes on any
// path.
func (s *sessionStore) gcLocked(now time.Time) {
	for id, rec := range s.m {
		if isExpiredAtStrict(rec.ExpiresAt, now) {
			delete(s.m, id)
		}
	}
	s.savesSinceGC = 0
}

func (s *sessionStore) maybeGCLocked(now time.Time) {
	s.savesSinceGC++
	if !sweepDue(s.savesSinceGC, sessionFullGCSaveInterval, len(s.m)) {
		return
	}
	s.gcLocked(now)
}

func (s *sessionStore) Find(_ context.Context, id string) (*store.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.m[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	return cloneSession(rec), nil
}

func (s *sessionStore) Touch(_ context.Context, id string, expiresAt, updatedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[id]
	if !ok {
		return store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return store.ErrNotFound
	}
	rec.ExpiresAt = expiresAt
	rec.UpdatedAt = updatedAt
	return nil
}

func (s *sessionStore) Delete(_ context.Context, id string) error {
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

func (s *sessionStore) ListByChooserGroup(_ context.Context, groupID string) ([]*store.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*store.Session, 0)
	for _, rec := range s.m {
		if rec.ChooserGroupID != groupID {
			continue
		}
		if isExpired(rec.ExpiresAt, s.clock) {
			continue
		}
		out = append(out, cloneSession(rec))
	}
	return out, nil
}

func cloneSession(s *store.Session) *store.Session {
	if s == nil {
		return nil
	}
	out := *s
	out.AMR = slices.Clone(s.AMR)
	return &out
}
