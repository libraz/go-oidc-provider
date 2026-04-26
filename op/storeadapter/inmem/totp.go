package inmem

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/libraz/go-oidc-provider/op/store"
)

// totpStore is the in-memory reference implementation of
// [store.TOTPStore]. It mirrors the read/write contract used by the
// other inmem substores: every Get clones the record so callers may
// mutate it freely, and every Put clones the supplied pointer so a
// later mutation by the caller does not leak into the map.
type totpStore struct {
	mu sync.RWMutex
	m  map[string]*store.TOTPRecord
}

func newTOTPStore() *totpStore {
	return &totpStore{m: make(map[string]*store.TOTPRecord)}
}

// Get implements [store.TOTPStore].
func (s *totpStore) Get(_ context.Context, subject string) (*store.TOTPRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.m[subject]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneTOTPRecord(rec), nil
}

// Put implements [store.TOTPStore]. The reference implementation has
// upsert semantics: a record at the same Subject is overwritten in
// place, matching the contract documented on the interface.
func (s *totpStore) Put(_ context.Context, r *store.TOTPRecord) error {
	if r == nil {
		return errors.New("inmem: nil totp record")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[r.Subject] = cloneTOTPRecord(r)
	return nil
}

// Delete implements [store.TOTPStore].
func (s *totpStore) Delete(_ context.Context, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[subject]; !ok {
		return store.ErrNotFound
	}
	delete(s.m, subject)
	return nil
}

func cloneTOTPRecord(r *store.TOTPRecord) *store.TOTPRecord {
	if r == nil {
		return nil
	}
	out := *r
	out.SecretCiphertext = slices.Clone(r.SecretCiphertext)
	return &out
}
