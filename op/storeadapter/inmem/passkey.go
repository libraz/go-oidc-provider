package inmem

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/libraz/go-oidc-provider/op/store"
)

// passkeyStore is the in-memory reference implementation of
// [store.PasskeyStore]. It mirrors the read/write contract used by the
// other inmem substores: every returned record is cloned so callers may
// mutate it freely, and every Put clones the supplied pointer so a later
// mutation by the caller does not leak into the map.
//
// The map is keyed on the hex encoding of the credential ID — a stable
// string we can use as a Go map key without copying the byte slice.
// The conversion is internal and never escapes; callers continue to
// pass raw [][]byte values through the public API.
type passkeyStore struct {
	mu sync.RWMutex
	m  map[string]*store.PasskeyRecord
}

func newPasskeyStore() *passkeyStore {
	return &passkeyStore{m: make(map[string]*store.PasskeyRecord)}
}

// Get implements [store.PasskeyStore].
func (s *passkeyStore) Get(_ context.Context, credentialID []byte) (*store.PasskeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.m[passkeyKey(credentialID)]
	if !ok {
		return nil, store.ErrNotFound
	}
	return clonePasskeyRecord(rec), nil
}

// ListBySubject implements [store.PasskeyStore]. The result is always
// a non-nil slice; an empty slice is the correct return when the
// subject has no registered passkeys.
func (s *passkeyStore) ListBySubject(_ context.Context, subject string) ([]*store.PasskeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*store.PasskeyRecord, 0)
	for _, rec := range s.m {
		if rec.Subject != subject {
			continue
		}
		out = append(out, clonePasskeyRecord(rec))
	}
	return out, nil
}

// Put implements [store.PasskeyStore]. The reference implementation
// has upsert semantics: a record at the same CredentialID is
// overwritten in place, matching the contract documented on the
// interface.
func (s *passkeyStore) Put(_ context.Context, r *store.PasskeyRecord) error {
	if r == nil {
		return errors.New("inmem: nil passkey record")
	}
	if len(r.CredentialID) == 0 {
		return errors.New("inmem: passkey record missing CredentialID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[passkeyKey(r.CredentialID)] = clonePasskeyRecord(r)
	return nil
}

// UpdateAssertion implements [store.PasskeyStore]. Holding the write
// lock across lookup, freshness comparison, and mutation is the
// reference implementation of the contract's atomicity requirement.
func (s *passkeyStore) UpdateAssertion(
	_ context.Context,
	credentialID []byte,
	update store.PasskeyAssertionUpdate,
) (*store.PasskeyRecord, error) {
	if len(credentialID) == 0 {
		return nil, errors.New("inmem: passkey assertion missing CredentialID")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.m[passkeyKey(credentialID)]
	if !ok {
		return nil, store.ErrNotFound
	}

	// CloneWarning is independent of counter freshness. A clone signal
	// observed by a stale concurrent assertion must remain sticky.
	rec.CloneWarning = rec.CloneWarning || update.CloneWarning

	counterless := rec.SignCount == 0 &&
		update.ExpectedSignCount == 0 &&
		update.SignCount == 0
	if update.SignCount > rec.SignCount || counterless {
		rec.SignCount = update.SignCount
		rec.UserPresent = update.UserPresent
		rec.UserVerified = update.UserVerified
		rec.BackupState = update.BackupState
	}

	return clonePasskeyRecord(rec), nil
}

// Delete implements [store.PasskeyStore].
func (s *passkeyStore) Delete(_ context.Context, credentialID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := passkeyKey(credentialID)
	if _, ok := s.m[k]; !ok {
		return store.ErrNotFound
	}
	delete(s.m, k)
	return nil
}

// passkeyKey converts a credential ID byte slice to the string used as
// the map key. Using a string ensures the map key is comparable
// independently of the slice's backing array; the conversion is a
// single allocation that never escapes the package.
func passkeyKey(credentialID []byte) string {
	return string(credentialID)
}

func clonePasskeyRecord(r *store.PasskeyRecord) *store.PasskeyRecord {
	if r == nil {
		return nil
	}
	out := *r
	out.CredentialID = bytes.Clone(r.CredentialID)
	out.PublicKey = bytes.Clone(r.PublicKey)
	out.AAGUID = bytes.Clone(r.AAGUID)
	out.Transports = slices.Clone(r.Transports)
	return &out
}
