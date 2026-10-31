package inmem

import (
	"context"
	"sync"

	"github.com/libraz/go-oidc-provider/op/store"
)

// --- MetadataStore -----------------------------------------------------------

type metadataStore struct {
	mu sync.RWMutex
	m  map[string]string
}

func newMetadataStore() *metadataStore {
	return &metadataStore{m: make(map[string]string)}
}

func (s *metadataStore) Get(_ context.Context, key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[key]
	if !ok {
		return "", store.ErrNotFound
	}
	return v, nil
}

func (s *metadataStore) Set(_ context.Context, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = value
	return nil
}
