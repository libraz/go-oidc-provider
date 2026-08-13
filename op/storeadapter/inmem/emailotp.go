package inmem

import (
	"context"
	"errors"
	"reflect"
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
// Records whose retention horizon is strictly before [Clock.Now()] are
// treated as absent: Get returns [store.ErrNotFound]. The horizon is
// [store.EmailOTPRecord.RetainUntil] (falling back to ExpiresAt when
// RetainUntil is zero) so the rate-limit / brute-force counters outlive
// the code's ExpiresAt — an expired code is still rejected by Consume /
// the verifier, but its counters remain readable while any window is
// live. The stale record is left in the map for diagnostic purposes;
// production backends typically run a sweeper, but the reference
// implementation deliberately omits one to keep the surface tiny.
type emailOTPStore struct {
	clock    Clock
	mu       sync.RWMutex
	m        map[string]*store.EmailOTPRecord
	versions *mfaVersionAllocator
}

func newEmailOTPStore(c Clock, versions ...*mfaVersionAllocator) *emailOTPStore {
	allocator := newMFAVersionAllocator()
	if len(versions) > 0 && versions[0] != nil {
		allocator = versions[0]
	}
	return &emailOTPStore{clock: c, m: make(map[string]*store.EmailOTPRecord), versions: allocator}
}

// Get implements [store.EmailOTPStore].
func (s *emailOTPStore) Get(_ context.Context, subject string) (*store.EmailOTPRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.m[subject]
	if !ok {
		return nil, store.ErrNotFound
	}
	// Retention is governed by RetainUntil (independent of the code's
	// ExpiresAt) so the rate-limit / brute-force counters survive an
	// expired code. RetainUntil==zero falls back to ExpiresAt so records
	// written before this field existed keep their old behaviour.
	horizon := rec.RetainUntil
	if horizon.IsZero() {
		horizon = rec.ExpiresAt
	}
	if !horizon.IsZero() && horizon.Before(s.now()) {
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
	version, err := s.versions.next()
	if err != nil {
		return err
	}
	stored := cloneEmailOTPRecord(r)
	stored.Version = version
	s.m[r.Subject] = stored
	return nil
}

// CompareAndSwap implements [store.EmailOTPStore].
func (s *emailOTPStore) CompareAndSwap(_ context.Context, previous, next *store.EmailOTPRecord) error {
	if next == nil || next.Subject == "" {
		return errors.New("inmem: invalid email otp compare-and-swap record")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.m[next.Subject]
	if previous == nil {
		if ok && !emailOTPExpired(current, s.now()) {
			return store.ErrAlreadyConsumed
		}
		version, err := s.versions.next()
		if err != nil {
			return err
		}
		stored := cloneEmailOTPRecord(next)
		stored.Version = version
		s.m[next.Subject] = stored
		return nil
	}
	if previous.Subject != next.Subject {
		return errors.New("inmem: invalid email otp compare-and-swap record")
	}
	if next.Version != previous.Version || !validMFARecordVersion(previous.Version) {
		return store.ErrAlreadyConsumed
	}
	if !ok || current.Version != previous.Version || !reflect.DeepEqual(current, previous) {
		return store.ErrAlreadyConsumed
	}
	version, err := s.versions.next()
	if err != nil {
		return err
	}
	stored := cloneEmailOTPRecord(next)
	stored.Version = version
	s.m[next.Subject] = stored
	return nil
}

// Consume implements [store.EmailOTPStore].
func (s *emailOTPStore) Consume(_ context.Context, r *store.EmailOTPRecord) error {
	if r == nil {
		return errors.New("inmem: nil email otp record")
	}
	if !validMFARecordVersion(r.Version) {
		return store.ErrAlreadyConsumed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.m[r.Subject]
	if !ok {
		return store.ErrNotFound
	}
	if current.Version != r.Version {
		return store.ErrAlreadyConsumed
	}
	if !current.ExpiresAt.IsZero() && current.ExpiresAt.Before(s.now()) {
		return store.ErrNotFound
	}
	if !current.ConsumedAt.IsZero() {
		return store.ErrAlreadyConsumed
	}
	// Consume receives the record after the verifier has stamped ConsumedAt
	// and cleared the failed-attempt state. Version plus the immutable code
	// material bind it to the exact challenge snapshot; requiring every
	// mutable counter to remain equal would reject a valid code after one
	// earlier typo.
	if !slices.Equal(current.CodeSalt, r.CodeSalt) || !slices.Equal(current.CodeHash, r.CodeHash) {
		return store.ErrAlreadyConsumed
	}
	stored := cloneEmailOTPRecord(r)
	// Marking the challenge is this method's job: a record the caller
	// left unstamped must not be written back as still-consumable, or
	// Consume reports success while the next reader can redeem it again.
	if stored.ConsumedAt.IsZero() {
		stored.ConsumedAt = s.now()
	}
	version, err := s.versions.next()
	if err != nil {
		return err
	}
	stored.Version = version
	s.m[r.Subject] = stored
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

func emailOTPExpired(rec *store.EmailOTPRecord, now time.Time) bool {
	if rec == nil {
		return true
	}
	horizon := rec.RetainUntil
	if horizon.IsZero() {
		horizon = rec.ExpiresAt
	}
	return !horizon.IsZero() && horizon.Before(now)
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
