package inmem

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/libraz/go-oidc-provider/op/store"
)

// --- InitialAccessTokenStore -------------------------------------------------

type iatStore struct {
	mu sync.Mutex
	m  map[string]*store.InitialAccessToken
	// byHash indexes records by [store.InitialAccessToken.HashedValue]
	// so [GetByHash] is a single map lookup rather than a linear scan
	// over m. The two maps share the same record pointer; mutations
	// through Put / IncrementUses are visible through both views.
	byHash map[string]*store.InitialAccessToken
}

func newIATStore() *iatStore {
	return &iatStore{
		m:      make(map[string]*store.InitialAccessToken),
		byHash: make(map[string]*store.InitialAccessToken),
	}
}

func (s *iatStore) Put(_ context.Context, t *store.InitialAccessToken) error {
	if t == nil {
		return errors.New("inmem: nil initial access token")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[t.ID]; exists {
		return store.ErrAlreadyExists
	}
	rec := cloneIAT(t)
	s.m[t.ID] = rec
	if rec.HashedValue != "" {
		s.byHash[rec.HashedValue] = rec
	}
	return nil
}

// GetByHash looks the IAT up by its [InitialAccessToken.HashedValue]
// in O(1) via the byHash index. The caller hashes the presented bearer
// secret (SHA-256, hex-encoded) and passes the digest verbatim; the
// constant-time compare against the stored digest is a structural
// belt-and-braces guard that guarantees safety even if a future
// refactor switches the index to a slice scan.
func (s *iatStore) GetByHash(_ context.Context, hash string) (*store.InitialAccessToken, error) {
	if hash == "" {
		return nil, store.ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.byHash[hash]
	if !ok {
		return nil, store.ErrNotFound
	}
	if !constantTimeKeyMatch(rec.HashedValue, hash) {
		return nil, store.ErrNotFound
	}
	return cloneIAT(rec), nil
}

// IncrementUses atomically increments the Uses counter and reports the new
// value. The contract test relies on this being read-modify-write under a
// single mutex; the reference implementation is single-process by design.
// IncrementUses returns [store.ErrConflict] when the new value would exceed
// MaxUses (with MaxUses==0 treated as a single-use ceiling of 1) so the
// caller can treat the attempt as a replay race rather than an absent IAT.
func (s *iatStore) IncrementUses(_ context.Context, id string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[id]
	if !ok {
		return 0, store.ErrNotFound
	}
	newUses := rec.Uses + 1
	ceiling := rec.MaxUses
	if ceiling == 0 {
		ceiling = 1
	}
	if newUses > ceiling {
		return rec.Uses, store.ErrConflict
	}
	rec.Uses = newUses
	return newUses, nil
}

func (s *iatStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[id]
	if !ok {
		return store.ErrNotFound
	}
	delete(s.m, id)
	if rec != nil && rec.HashedValue != "" {
		// Only drop the byHash entry when it still points at this
		// record; a colliding HashedValue rotation could otherwise
		// orphan the surviving entry.
		if cur, present := s.byHash[rec.HashedValue]; present && cur == rec {
			delete(s.byHash, rec.HashedValue)
		}
	}
	return nil
}

func cloneIAT(t *store.InitialAccessToken) *store.InitialAccessToken {
	if t == nil {
		return nil
	}
	out := *t
	out.AllowedScopes = slices.Clone(t.AllowedScopes)
	return &out
}
