package inmem

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/libraz/go-oidc-provider/op/store"
)

type authCodeStore struct {
	mu    sync.RWMutex
	clock Clock
	m     map[string]*store.AuthorizationCode
}

func newAuthCodeStore(c Clock) *authCodeStore {
	return &authCodeStore{clock: c, m: make(map[string]*store.AuthorizationCode)}
}

func (s *authCodeStore) Save(_ context.Context, code *store.AuthorizationCode) error {
	if code == nil {
		return errors.New("inmem: nil authorization code")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashKey(code.ID)
	if _, exists := s.m[key]; exists {
		return store.ErrAlreadyExists
	}
	stored := cloneAuthCode(code)
	// Drop the raw ID from the stored record. The map key is the
	// hashed token; the stored record retains the hash so callers
	// inspecting the underlying map see only the digest, never the
	// bearer secret. Find / Consume restore the raw ID from the
	// lookup parameter before handing the record back.
	stored.ID = key
	s.m[key] = stored
	return nil
}

func (s *authCodeStore) Find(_ context.Context, id string) (*store.AuthorizationCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := hashKey(id)
	rec, ok := s.m[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	if !constantTimeKeyMatch(rec.ID, key) {
		// Defensive: the digest stored alongside the record diverged
		// from the map key. The reference impl maintains the
		// invariant; the check guards against a future refactor.
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	out := cloneAuthCode(rec)
	out.ID = id
	return out, nil
}

func (s *authCodeStore) Consume(_ context.Context, id string) (*store.AuthorizationCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashKey(id)
	rec, ok := s.m[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	if !constantTimeKeyMatch(rec.ID, key) {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	if rec.ConsumedAt != nil {
		out := cloneAuthCode(rec)
		out.ID = id
		return out, store.ErrAlreadyConsumed
	}
	now := s.clock.Now()
	rec.ConsumedAt = &now
	out := cloneAuthCode(rec)
	out.ID = id
	return out, nil
}

func cloneAuthCode(c *store.AuthorizationCode) *store.AuthorizationCode {
	if c == nil {
		return nil
	}
	out := *c
	out.Scope = slices.Clone(c.Scope)
	out.Resource = c.Resource
	if c.ConsumedAt != nil {
		t := *c.ConsumedAt
		out.ConsumedAt = &t
	}
	return &out
}
