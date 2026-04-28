package inmem

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// emailOTPStore is the in-memory reference implementation of
// [store.EmailOTPStore]. It mirrors the contract used by the other
// inmem substores: every Get clones the record so callers may mutate
// it freely, and every Put clones the supplied pointer so a later
// mutation by the caller does not leak into the map.
//
// Records whose ExpiresAt is strictly before [Clock.Now()] are treated
// as absent: Get returns [store.ErrNotFound]. The expired record is
// left in the map for diagnostic purposes; production backends
// typically run a sweeper, but the reference implementation
// deliberately omits one to keep the surface tiny.
type emailOTPStore struct {
	clock Clock
	mu    sync.RWMutex
	m     map[string]*store.EmailOTPRecord
}

func newEmailOTPStore(c Clock) *emailOTPStore {
	return &emailOTPStore{clock: c, m: make(map[string]*store.EmailOTPRecord)}
}

// Get implements [store.EmailOTPStore].
func (s *emailOTPStore) Get(_ context.Context, subject string) (*store.EmailOTPRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.m[subject]
	if !ok {
		return nil, store.ErrNotFound
	}
	if !rec.ExpiresAt.IsZero() && rec.ExpiresAt.Before(s.now()) {
		return nil, store.ErrNotFound
	}
	return cloneEmailOTPRecord(rec), nil
}

// Put implements [store.EmailOTPStore]. The reference implementation has
// upsert semantics: a record at the same Subject is overwritten in
// place, matching the contract documented on the interface.
func (s *emailOTPStore) Put(_ context.Context, r *store.EmailOTPRecord) error {
	if r == nil {
		return errors.New("inmem: nil email otp record")
	}
	if r.Subject == "" {
		return errors.New("inmem: email otp record missing Subject")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[r.Subject] = cloneEmailOTPRecord(r)
	return nil
}

// Delete implements [store.EmailOTPStore].
func (s *emailOTPStore) Delete(_ context.Context, subject string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[subject]; !ok {
		return store.ErrNotFound
	}
	delete(s.m, subject)
	return nil
}

func (s *emailOTPStore) now() time.Time {
	if s.clock == nil {
		return timex.SystemClock.Now()
	}
	return s.clock.Now()
}

func cloneEmailOTPRecord(r *store.EmailOTPRecord) *store.EmailOTPRecord {
	if r == nil {
		return nil
	}
	out := *r
	out.CodeSalt = slices.Clone(r.CodeSalt)
	out.CodeHash = slices.Clone(r.CodeHash)
	return &out
}
