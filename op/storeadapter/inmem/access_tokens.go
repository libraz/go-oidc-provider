package inmem

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// accessTokenStore is the inmem implementation of
// [store.AccessTokenRegistry]. It keeps every issued JWT access-token
// shadow row keyed by JTI; revocation flips a boolean so audit
// downstream can still recover the issuance metadata. The periodic GC
// sweep drops rows whose ExpiresAt is past the supplied cutoff,
// bounding storage to the active TTL plus the configured grace.
type accessTokenStore struct {
	mu sync.RWMutex
	m  map[string]*store.AccessTokenRecord
}

func newAccessTokenStore() *accessTokenStore {
	return &accessTokenStore{m: make(map[string]*store.AccessTokenRecord)}
}

// Register implements [store.AccessTokenRegistry].
func (s *accessTokenStore) Register(_ context.Context, rec store.AccessTokenRecord) error {
	if rec.JTI == "" {
		return errors.New("inmem: AccessTokenRecord requires a non-empty JTI")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.m[rec.JTI]; exists {
		return store.ErrAlreadyExists
	}
	s.m[rec.JTI] = cloneAccessToken(&rec)
	return nil
}

// Find implements [store.AccessTokenRegistry]. Returns (nil, nil) when
// the record is absent so callers can distinguish "not registered"
// from a genuine error path.
func (s *accessTokenStore) Find(_ context.Context, jti string) (*store.AccessTokenRecord, error) {
	if jti == "" {
		return nil, nil //nolint:nilnil // contract permits (nil, nil) for absent records.
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.m[jti]
	if !ok {
		return nil, nil //nolint:nilnil // contract permits (nil, nil) for absent records.
	}
	return cloneAccessToken(rec), nil
}

// RevokeByJTI implements [store.AccessTokenRegistry]. The call is
// idempotent: a missing record returns nil so the revocation endpoint
// can stay aligned with RFC 7009 §2.2.
func (s *accessTokenStore) RevokeByJTI(_ context.Context, jti string) error {
	if jti == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[jti]
	if !ok {
		return nil
	}
	rec.Revoked = true
	return nil
}

// RevokeByGrant implements [store.AccessTokenRegistry]. Returns the
// number of rows the call flipped (rows already revoked are not
// counted; the caller can detect "first-time cascade" by inspecting
// the return).
func (s *accessTokenStore) RevokeByGrant(_ context.Context, grantID string) (int, error) {
	if grantID == "" {
		return 0, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, rec := range s.m {
		if rec.GrantID != grantID {
			continue
		}
		if rec.Revoked {
			continue
		}
		rec.Revoked = true
		n++
	}
	return n, nil
}

// GC implements [store.AccessTokenRegistry]. Drops every record whose
// ExpiresAt is strictly before cutoff. The zero time is treated as
// "no expiry" and is never collected; callers that need the original
// behaviour (drop everything) supply an explicit far-future cutoff.
func (s *accessTokenStore) GC(_ context.Context, cutoff time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for jti, rec := range s.m {
		if rec.ExpiresAt.IsZero() {
			continue
		}
		if rec.ExpiresAt.Before(cutoff) {
			delete(s.m, jti)
			n++
		}
	}
	return n, nil
}

func cloneAccessToken(rec *store.AccessTokenRecord) *store.AccessTokenRecord {
	if rec == nil {
		return nil
	}
	out := *rec
	out.Scopes = slices.Clone(rec.Scopes)
	return &out
}
