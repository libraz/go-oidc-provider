package inmem

import (
	"context"
	"slices"
	"sync"

	"github.com/libraz/go-oidc-provider/op/store"
)

// --- UserStore ---------------------------------------------------------------

type userStore struct {
	mu        sync.RWMutex
	m         map[string]*store.User
	usernames map[string]string // username → subject
	hashes    map[string][]byte // subject → PHC-encoded password hash
}

func newUserStore() *userStore {
	return &userStore{
		m:         make(map[string]*store.User),
		usernames: make(map[string]string),
		hashes:    make(map[string][]byte),
	}
}

func (s *userStore) FindBySubject(_ context.Context, sub string) (*store.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.m[sub]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneUser(u), nil
}

func (s *userStore) FindByUsername(_ context.Context, username string) (*store.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sub, ok := s.usernames[username]
	if !ok {
		return nil, store.ErrNotFound
	}
	u, ok := s.m[sub]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneUser(u), nil
}

func (s *userStore) ReadPasswordHash(_ context.Context, subject string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	hash, ok := s.hashes[subject]
	if !ok || len(hash) == 0 {
		return nil, store.ErrNotFound
	}
	return slices.Clone(hash), nil
}

// UpdatePasswordHash implements [store.UserPasswordHashUpdater].
func (s *userStore) UpdatePasswordHash(_ context.Context, subject string, encoded []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[subject]; !ok {
		return store.ErrNotFound
	}
	s.hashes[subject] = slices.Clone(encoded)
	return nil
}

func (s *userStore) put(u *store.User) {
	if u == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[u.Subject] = cloneUser(u)
}

func (s *userStore) putWithPassword(u *store.User, username string, hash []byte) {
	if u == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[u.Subject] = cloneUser(u)
	if username != "" {
		s.usernames[username] = u.Subject
	}
	if len(hash) > 0 {
		s.hashes[u.Subject] = slices.Clone(hash)
	}
}

func cloneUser(u *store.User) *store.User {
	if u == nil {
		return nil
	}
	out := *u
	out.Claims = cloneMap(u.Claims)
	return &out
}
