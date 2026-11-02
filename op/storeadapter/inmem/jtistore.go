package inmem

import (
	"context"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// --- ConsumedJTIStore --------------------------------------------------------

type jtiStore struct {
	mu           sync.RWMutex
	clock        Clock
	m            map[string]time.Time
	marksSinceGC sweeper
}

func newJTIStore(c Clock) *jtiStore {
	return &jtiStore{clock: c, m: make(map[string]time.Time)}
}

// Mark hashes the supplied jti via [patterns.Digest] before keying
// the map so the raw bearer is never retained in process memory. JWT
// IDs are caller-supplied strings (RFC 7519 sets no upper bound) and a
// heap dump that contains the raw values would let an attacker replay
// proofs against another OP that signed the same key. The digest is
// not a secret; its only purpose is bounded length and one-way derivation.
func (s *jtiStore) Mark(_ context.Context, jti string, expiresAt time.Time) error {
	digest := patterns.Digest(jti)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	if existing, ok := s.m[digest]; ok {
		// Treat expired entries as absent so a fresh mark may succeed.
		if !patterns.IsExpiredInclusive(existing, now) {
			return store.ErrAlreadyConsumed
		}
		delete(s.m, digest)
	}
	s.maybeGCJTILocked(now)
	s.m[digest] = expiresAt
	return nil
}

// Has reports whether jti is still marked. The expiry bound is the
// inclusive one [jtiStore.Mark] applies (a marker is expired from its
// expiresAt onwards), so the two methods cannot disagree at the boundary
// instant about whether a jti is consumed; see [store.ConsumedJTIStore].
func (s *jtiStore) Has(_ context.Context, jti string) (bool, error) {
	digest := patterns.Digest(jti)
	s.mu.RLock()
	defer s.mu.RUnlock()
	expiresAt, ok := s.m[digest]
	if !ok {
		return false, nil
	}
	if patterns.IsExpiredInclusive(expiresAt, s.clock.Now()) {
		return false, nil
	}
	return true, nil
}

func (s *jtiStore) maybeGCJTILocked(now time.Time) {
	if !s.marksSinceGC.due(len(s.m)) {
		return
	}
	for digest, expiresAt := range s.m {
		if patterns.IsExpiredInclusive(expiresAt, now) {
			delete(s.m, digest)
		}
	}
}
