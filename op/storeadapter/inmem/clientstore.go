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

func (s *clientStore) ReconcileStatic(ctx context.Context, clients []*store.Client) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	next := make(map[string]*store.Client, len(s.m)+len(clients))
	for id, client := range s.m {
		next[id] = client
	}
	seen := make(map[string]struct{}, len(clients))
	for _, desired := range clients {
		if err := validateStaticClient(ctx, desired, seen); err != nil {
			return err
		}
		if existing, ok := s.m[desired.ID]; ok {
			if !store.StaticClientEquivalent(existing, desired) {
				return store.ErrConflict
			}
			continue
		}
		next[desired.ID] = cloneClient(desired)
	}
	s.m = next
	return nil
}

func validateStaticClient(
	ctx context.Context,
	desired *store.Client,
	seen map[string]struct{},
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if desired == nil {
		return errors.New("inmem: nil static client")
	}
	if desired.Source != "" && desired.Source != store.ClientSourceStatic {
		return store.ErrConflict
	}
	if _, duplicate := seen[desired.ID]; duplicate {
		return store.ErrConflict
	}
	seen[desired.ID] = struct{}{}
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
