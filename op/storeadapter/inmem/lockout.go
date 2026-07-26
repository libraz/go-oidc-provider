package inmem

import (
	"context"
	"errors"
	"math"
	"sync"

	"github.com/libraz/go-oidc-provider/op/store"
)

// authnLockoutStore is the in-memory reference implementation of
// [store.AuthnLockoutStore]. It mirrors the contract used by the other
// inmem substores: every Get clones the record so callers may mutate it
// freely, and every successful CompareAndSwap clones the supplied pointer
// so a later mutation by the caller does not leak into the map.
//
// The version comparison and replacement happen while holding the
// same mutex. This makes every lockout transition atomic, including
// races between failure increments, window rollover, and success
// reset.
type authnLockoutStore struct {
	mu sync.Mutex
	m  map[string]*store.AuthnLockoutRecord
}

func newAuthnLockoutStore() *authnLockoutStore {
	return &authnLockoutStore{m: make(map[string]*store.AuthnLockoutRecord)}
}

// Get implements [store.AuthnLockoutStore].
func (s *authnLockoutStore) Get(ctx context.Context, subject string) (*store.AuthnLockoutRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[subject]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneAuthnLockoutRecord(rec), nil
}

// CompareAndSwap implements [store.AuthnLockoutStore].
func (s *authnLockoutStore) CompareAndSwap(ctx context.Context, expectedVersion uint64, next *store.AuthnLockoutRecord) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if next == nil {
		return false, errors.New("inmem: nil authn lockout record")
	}
	if next.Subject == "" {
		return false, errors.New("inmem: authn lockout record missing Subject")
	}
	if expectedVersion == math.MaxUint64 {
		return false, errors.New("inmem: authn lockout version overflow")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	current, ok := s.m[next.Subject]
	if !ok {
		if expectedVersion != 0 {
			return false, nil
		}
	} else if expectedVersion == 0 || current.Version != expectedVersion {
		return false, nil
	}

	persisted := cloneAuthnLockoutRecord(next)
	persisted.Version = expectedVersion + 1
	s.m[next.Subject] = persisted
	return true, nil
}

func cloneAuthnLockoutRecord(r *store.AuthnLockoutRecord) *store.AuthnLockoutRecord {
	if r == nil {
		return nil
	}
	out := *r
	return &out
}
