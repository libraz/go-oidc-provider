package inmem

import (
	"bytes"
	"context"
	"errors"
	"math"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/libraz/go-oidc-provider/op/store"
)

// totpStore is the in-memory reference implementation of
// [store.TOTPStore]. It mirrors the read/write contract used by the
// other inmem substores: every Get clones the record so callers may
// mutate it freely, and every Put clones the supplied pointer so a
// later mutation by the caller does not leak into the map.
type totpStore struct {
	mu       sync.RWMutex
	m        map[string]*store.TOTPRecord
	versions *mfaVersionAllocator
}

func newTOTPStore(versions ...*mfaVersionAllocator) *totpStore {
	allocator := newMFAVersionAllocator()
	if len(versions) > 0 && versions[0] != nil {
		allocator = versions[0]
	}
	return &totpStore{m: make(map[string]*store.TOTPRecord), versions: allocator}
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
	version, err := s.versions.next()
	if err != nil {
		return err
	}
	stored := cloneTOTPRecord(r)
	stored.Version = version
	s.m[r.Subject] = stored
	return nil
}

// CompareAndSwap implements [store.TOTPStore].
func (s *totpStore) CompareAndSwap(_ context.Context, previous, next *store.TOTPRecord) error {
	if previous == nil || next == nil || previous.Subject == "" || next.Subject != previous.Subject {
		return errors.New("inmem: invalid totp compare-and-swap record")
	}
	if next.Version != previous.Version || !validMFARecordVersion(previous.Version) {
		return store.ErrAlreadyConsumed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.m[previous.Subject]
	if !ok || current.Version != previous.Version || !reflect.DeepEqual(current, previous) {
		return store.ErrAlreadyConsumed
	}
	version, err := s.versions.next()
	if err != nil {
		return err
	}
	stored := cloneTOTPRecord(next)
	stored.Version = version
	s.m[next.Subject] = stored
	return nil
}

// Accept implements [store.TOTPStore].
func (s *totpStore) Accept(_ context.Context, r *store.TOTPRecord) error {
	if r == nil {
		return errors.New("inmem: nil totp record")
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
	if !bytes.Equal(current.SecretCiphertext, r.SecretCiphertext) || !current.ConfirmedAt.Equal(r.ConfirmedAt) {
		return store.ErrAlreadyConsumed
	}
	if r.LastAcceptedStep == 0 || current.LastAcceptedStep >= r.LastAcceptedStep {
		return store.ErrAlreadyConsumed
	}
	version, err := s.versions.next()
	if err != nil {
		return err
	}
	stored := cloneTOTPRecord(r)
	stored.Version = version
	s.m[r.Subject] = stored
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

const maxMFARecordVersion = uint64(math.MaxInt64)

// mfaVersionAllocator issues process-local, never-reused generations for
// both factor stores. The allocator belongs to Store, rather than to a map
// entry, so deleting and recreating a subject cannot bring an old snapshot's
// opaque token back into circulation. Gaps are harmless when a conditional
// write loses a race.
type mfaVersionAllocator struct {
	nextValue atomic.Uint64
}

func newMFAVersionAllocator() *mfaVersionAllocator {
	return &mfaVersionAllocator{}
}

func (a *mfaVersionAllocator) next() (uint64, error) {
	for {
		current := a.nextValue.Load()
		if current >= maxMFARecordVersion-1 {
			return 0, errors.New("inmem: mfa record version exhausted")
		}
		candidate := current + 1
		if a.nextValue.CompareAndSwap(current, candidate) {
			return candidate, nil
		}
	}
}

func validMFARecordVersion(version uint64) bool {
	return version > 0 && version < maxMFARecordVersion
}

func cloneTOTPRecord(r *store.TOTPRecord) *store.TOTPRecord {
	if r == nil {
		return nil
	}
	out := *r
	out.SecretCiphertext = slices.Clone(r.SecretCiphertext)
	return &out
}
