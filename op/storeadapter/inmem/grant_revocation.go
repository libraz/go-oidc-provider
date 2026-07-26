package inmem

import (
	"context"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// grantRevocationStore is the inmem implementation of
// [store.GrantRevocationStore]. It keeps two maps under one mutex:
// one keyed by GrantID for grant tombstones and one keyed by JTI for
// the denylist of single-AT revocations. The split mirrors how
// production backends are expected to lay the rows out (two physical
// tables) so the contract test exercises the same semantics that a
// SQL adapter satisfies.
//
// The reference implementation does not hash the keys: GrantID is an
// internal identifier (never exposed on the wire) and JTI is a
// non-secret RFC 7519 claim, so the hash-on-store contract that applies
// to bearer secrets does not apply here.
type grantRevocationStore struct {
	mu         sync.RWMutex
	tombstones map[string]*store.GrantTombstone
	denylist   map[string]*store.RevokedJTI
}

func newGrantRevocationStore() *grantRevocationStore {
	return &grantRevocationStore{
		tombstones: make(map[string]*store.GrantTombstone),
		denylist:   make(map[string]*store.RevokedJTI),
	}
}

// RevokeGrant implements [store.GrantRevocationStore]. The call is
// idempotent: a second call against the same GrantID extends both
// RevokedAt and ExpiresAt to the max of the supplied and existing
// values. Advancing RevokedAt is required because the OP reuses an
// existing (subject, client) Grant across repeat /authorize flows; if
// a fresh auth flow issued a new AT under the grant after an earlier
// cascade, a follow-up cascade must extend RevokedAt to cover those
// new ATs as well, otherwise the verifier's "iat <= RevokedAt" rule
// silently lets them through. Reason is updated only when the
// existing row has none so an audit trail latches onto the first
// hint.
//
// An empty GrantID is a no-op so the call site can shed cascade calls
// for grants that have no authorize-side identifier without a guard.
func (s *grantRevocationStore) RevokeGrant(_ context.Context, t store.GrantTombstone) error {
	if t.GrantID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.tombstones[t.GrantID]; ok {
		if t.RevokedAt.After(existing.RevokedAt) {
			existing.RevokedAt = t.RevokedAt
		}
		if t.ExpiresAt.After(existing.ExpiresAt) {
			existing.ExpiresAt = t.ExpiresAt
		}
		if existing.Reason == "" && t.Reason != "" {
			existing.Reason = t.Reason
		}
		return nil
	}
	clone := t
	s.tombstones[t.GrantID] = &clone
	return nil
}

// RevokeJTI implements [store.GrantRevocationStore]. The call is
// idempotent: a second call against the same JTI is a no-op (the
// existing row's ExpiresAt is left unchanged so the audit trail of when
// the row was first written is preserved).
//
// An empty JTI is a no-op.
func (s *grantRevocationStore) RevokeJTI(_ context.Context, r store.RevokedJTI) error {
	if r.JTI == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.denylist[r.JTI]; ok {
		return nil
	}
	clone := r
	s.denylist[r.JTI] = &clone
	return nil
}

// IsRevoked implements [store.GrantRevocationStore]. The lookup order
// is JTI denylist first (cheap, small) then grant tombstone with the
// rule "revoked iff !iat.After(tombstone.RevokedAt)". The reference
// implementation never returns a transport-fault error; embedders that
// wrap a remote backend MAY return one and the verifier treats it as
// fatal.
func (s *grantRevocationStore) IsRevoked(_ context.Context, grantID, jti string, iat time.Time) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if jti != "" {
		if _, ok := s.denylist[jti]; ok {
			return true, nil
		}
	}
	if grantID == "" {
		return false, nil
	}
	tomb, ok := s.tombstones[grantID]
	if !ok {
		return false, nil
	}
	// "revoked iff iat <= RevokedAt": equivalently, NOT iat.After.
	if !iat.After(tomb.RevokedAt) {
		return true, nil
	}
	return false, nil
}

// GC implements [store.GrantRevocationStore]. Drops every tombstone and
// denylist row whose ExpiresAt is strictly before cutoff. Records whose
// ExpiresAt is the zero time opt out of GC, mirroring the access-token
// substore so callers cannot inadvertently drop a row that was written
// without a TTL.
func (s *grantRevocationStore) GC(_ context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for id, tomb := range s.tombstones {
		if tomb.ExpiresAt.IsZero() {
			continue
		}
		if tomb.ExpiresAt.Before(cutoff) {
			delete(s.tombstones, id)
			n++
		}
	}
	for jti, row := range s.denylist {
		if row.ExpiresAt.IsZero() {
			continue
		}
		if row.ExpiresAt.Before(cutoff) {
			delete(s.denylist, jti)
			n++
		}
	}
	return n, nil
}
