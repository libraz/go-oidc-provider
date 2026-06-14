package inmem

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// authnLockoutStore is the in-memory reference implementation of
// [store.AuthnLockoutStore]. It mirrors the contract used by the other
// inmem substores: every Get clones the record so callers may mutate it
// freely, and every Put clones the supplied pointer so a later mutation
// by the caller does not leak into the map.
//
// The implementation guards the entire read-modify-write on Increment
// with the same mutex Get / Put hold, so a concurrent Increment cannot
// observe a stale FailedCount and lose an update (M-AUTHN-4). Production
// SQL backends solve the same race with
// "UPDATE ... SET failed_count = failed_count + 1".
type authnLockoutStore struct {
	mu sync.Mutex
	m  map[string]*store.AuthnLockoutRecord
}

func newAuthnLockoutStore() *authnLockoutStore {
	return &authnLockoutStore{m: make(map[string]*store.AuthnLockoutRecord)}
}

// Get implements [store.AuthnLockoutStore].
func (s *authnLockoutStore) Get(_ context.Context, subject string) (*store.AuthnLockoutRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[subject]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneAuthnLockoutRecord(rec), nil
}

// Put implements [store.AuthnLockoutStore].
func (s *authnLockoutStore) Put(_ context.Context, r *store.AuthnLockoutRecord) error {
	if r == nil {
		return errors.New("inmem: nil authn lockout record")
	}
	if r.Subject == "" {
		return errors.New("inmem: authn lockout record missing Subject")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[r.Subject] = cloneAuthnLockoutRecord(r)
	return nil
}

// Increment implements [store.AuthnLockoutStore]. The mutex around the
// read-modify-write is the inmem analogue of the SQL atomic increment.
func (s *authnLockoutStore) Increment(_ context.Context, subject string, now time.Time) (int, error) {
	if subject == "" {
		return 0, errors.New("inmem: authn lockout increment requires non-empty subject")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[subject]
	if !ok {
		rec = &store.AuthnLockoutRecord{
			Subject:        subject,
			FailedCount:    0,
			FirstFailureAt: now,
		}
	}
	rec.FailedCount++
	if rec.FirstFailureAt.IsZero() {
		rec.FirstFailureAt = now
	}
	s.m[subject] = rec
	return rec.FailedCount, nil
}

// StampLock implements [store.AuthnLockoutStamper]. The mutex makes the
// LockedUntil write atomic with respect to a concurrent Increment, so the
// lockout stamp cannot overwrite (and thereby lose) an increment that lands
// between the helper's threshold check and this call (M-AUTHN-4).
func (s *authnLockoutStore) StampLock(_ context.Context, subject string, lockedUntil time.Time) error {
	if subject == "" {
		return errors.New("inmem: authn lockout stamp requires non-empty subject")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[subject]
	if !ok {
		return store.ErrNotFound
	}
	rec.LockedUntil = lockedUntil
	return nil
}

func cloneAuthnLockoutRecord(r *store.AuthnLockoutRecord) *store.AuthnLockoutRecord {
	if r == nil {
		return nil
	}
	out := *r
	return &out
}
