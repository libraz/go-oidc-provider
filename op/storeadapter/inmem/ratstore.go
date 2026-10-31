package inmem

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/libraz/go-oidc-provider/op/store"
)

// --- RegistrationAccessTokenStore --------------------------------------------

type ratStore struct {
	mu sync.Mutex
	m  map[string]*store.RegistrationAccessToken
}

func newRATStore() *ratStore {
	return &ratStore{m: make(map[string]*store.RegistrationAccessToken)}
}

func (s *ratStore) Put(_ context.Context, t *store.RegistrationAccessToken) error {
	if t == nil {
		return errors.New("inmem: nil registration access token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[t.ClientID] = cloneRAT(t)
	return nil
}

func (s *ratStore) GetByClientID(_ context.Context, clientID string) (*store.RegistrationAccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[clientID]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneRAT(rec), nil
}

func (s *ratStore) Delete(_ context.Context, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[clientID]; !ok {
		return store.ErrNotFound
	}
	delete(s.m, clientID)
	return nil
}

func cloneRAT(t *store.RegistrationAccessToken) *store.RegistrationAccessToken {
	if t == nil {
		return nil
	}
	out := *t
	out.AllowedScopes = slices.Clone(t.AllowedScopes)
	return &out
}
