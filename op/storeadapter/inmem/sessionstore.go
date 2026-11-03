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

// --- SessionStore ------------------------------------------------------------

type sessionStore struct {
	mu           sync.RWMutex
	clock        Clock
	m            map[string]*store.Session
	byGroup      map[string]map[string]struct{} // ChooserGroupID -> session ids
	bySubject    map[string]map[string]struct{} // Subject -> session ids
	savesSinceGC sweeper
}

var _ store.SessionSubjectDeleter = (*sessionStore)(nil)

func newSessionStore(c Clock) *sessionStore {
	return &sessionStore{
		clock:     c,
		m:         make(map[string]*store.Session),
		byGroup:   make(map[string]map[string]struct{}),
		bySubject: make(map[string]map[string]struct{}),
	}
}

func (s *sessionStore) Save(_ context.Context, sess *store.Session) error {
	if sess == nil {
		return errors.New("inmem: nil session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeGCLocked(s.clock.Now())
	s.dropLocked(sess.ID)
	stored := cloneSession(sess)
	s.m[sess.ID] = stored
	ids := s.byGroup[stored.ChooserGroupID]
	if ids == nil {
		ids = make(map[string]struct{})
		s.byGroup[stored.ChooserGroupID] = ids
	}
	ids[sess.ID] = struct{}{}
	subIDs := s.bySubject[stored.Subject]
	if subIDs == nil {
		subIDs = make(map[string]struct{})
		s.bySubject[stored.Subject] = subIDs
	}
	subIDs[sess.ID] = struct{}{}
	return nil
}

// DeleteBySubject implements [store.SessionSubjectDeleter]. It removes
// every session of subject, expired or not, and returns nil when there
// is none.
func (s *sessionStore) DeleteBySubject(ctx context.Context, subject string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if subject == "" {
		return errors.New("inmem: empty subject")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// dropLocked mutates the index set, so snapshot the ids first.
	ids := make([]string, 0, len(s.bySubject[subject]))
	for id := range s.bySubject[subject] {
		ids = append(ids, id)
	}
	for _, id := range ids {
		s.dropLocked(id)
	}
	return nil
}

// dropLocked removes the session id from the primary map and from the
// chooser-group and subject indexes. The caller must hold sessionStore.mu
// for writing.
func (s *sessionStore) dropLocked(id string) {
	rec, ok := s.m[id]
	if !ok {
		return
	}
	delete(s.m, id)
	if ids := s.byGroup[rec.ChooserGroupID]; ids != nil {
		delete(ids, id)
		if len(ids) == 0 {
			delete(s.byGroup, rec.ChooserGroupID)
		}
	}
	if ids := s.bySubject[rec.Subject]; ids != nil {
		delete(ids, id)
		if len(ids) == 0 {
			delete(s.bySubject, rec.Subject)
		}
	}
}

// gcLocked drops every session whose ExpiresAt has passed. Find, Touch,
// ListByChooserGroup, and Delete all treat an expired session as
// absent, so removing it cannot change what a caller observes on any
// path.
func (s *sessionStore) gcLocked(now time.Time) {
	for id, rec := range s.m {
		if patterns.IsExpiredStrict(rec.ExpiresAt, now) {
			s.dropLocked(id)
		}
	}
}

func (s *sessionStore) maybeGCLocked(now time.Time) {
	if s.savesSinceGC.due(len(s.m)) {
		s.gcLocked(now)
	}
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
	s.dropLocked(id)
	if isExpired(rec.ExpiresAt, s.clock) {
		return store.ErrNotFound
	}
	return nil
}

func (s *sessionStore) ListByChooserGroup(_ context.Context, groupID string) ([]*store.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*store.Session, 0)
	for id := range s.byGroup[groupID] {
		rec := s.m[id]
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
