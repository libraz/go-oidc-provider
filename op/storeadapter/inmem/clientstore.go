package inmem

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/libraz/go-oidc-provider/op/store"
)

type clientStore struct {
	mu sync.RWMutex
	m  map[string]*store.Client
}

func newClientStore() *clientStore {
	return &clientStore{m: make(map[string]*store.Client)}
}

func (s *clientStore) GetClient(_ context.Context, id string) (*store.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.m[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneClient(c), nil
}

func (s *clientStore) Register(_ context.Context, c *store.Client) error {
	if c == nil {
		return errors.New("inmem: nil client")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[c.ID]; exists {
		return store.ErrAlreadyExists
	}
	s.m[c.ID] = cloneClient(c)
	return nil
}

func (s *clientStore) Update(_ context.Context, c *store.Client) error {
	if c == nil {
		return errors.New("inmem: nil client")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[c.ID]; !exists {
		return store.ErrNotFound
	}
	s.m[c.ID] = cloneClient(c)
	return nil
}

func (s *clientStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[id]; !exists {
		return store.ErrNotFound
	}
	delete(s.m, id)
	return nil
}

func cloneClient(c *store.Client) *store.Client {
	if c == nil {
		return nil
	}
	out := *c
	out.RedirectURIs = slices.Clone(c.RedirectURIs)
	out.PostLogoutRedirectURIs = slices.Clone(c.PostLogoutRedirectURIs)
	out.GrantTypes = slices.Clone(c.GrantTypes)
	out.ResponseTypes = slices.Clone(c.ResponseTypes)
	out.Scopes = slices.Clone(c.Scopes)
	out.Resources = slices.Clone(c.Resources)
	out.Contacts = slices.Clone(c.Contacts)
	out.DefaultACRValues = slices.Clone(c.DefaultACRValues)
	out.RequestURIs = slices.Clone(c.RequestURIs)
	if c.DefaultMaxAge != nil {
		v := *c.DefaultMaxAge
		out.DefaultMaxAge = &v
	}
	if len(c.JWKs) > 0 {
		out.JWKs = append([]byte(nil), c.JWKs...)
	}
	return &out
}
