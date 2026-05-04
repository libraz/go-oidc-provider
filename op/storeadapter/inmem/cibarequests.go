package inmem

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// cibaRequestStore is the in-memory implementation of
// [store.CIBARequestStore]. The primary map is keyed on the SHA-256
// digest of the wire auth_req_id so a heap dump cannot reconstruct the
// bearer secret. Unlike [deviceCodeStore], CIBA has no user_code
// channel, so a single hash-keyed map is sufficient.
type cibaRequestStore struct {
	mu    sync.RWMutex
	clock Clock
	m     map[string]*store.CIBARequest // key: hashKey(auth_req_id)
}

func newCIBARequestStore(c Clock) *cibaRequestStore {
	return &cibaRequestStore{
		clock: c,
		m:     make(map[string]*store.CIBARequest),
	}
}

func (s *cibaRequestStore) Save(_ context.Context, req *store.CIBARequest) error {
	if req == nil {
		return errors.New("inmem: nil ciba request")
	}
	if req.Status == 0 {
		// Caller forgot to stamp the status; default to Pending so
		// the lifecycle starts from a known state.
		req.Status = store.CIBARequestStatusPending
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashKey(req.ID)
	if _, exists := s.m[key]; exists {
		return store.ErrAlreadyExists
	}
	stored := cloneCIBARequest(req)
	stored.ID = key
	s.m[key] = stored
	return nil
}

func (s *cibaRequestStore) FindByAuthReqID(_ context.Context, authReqID string) (*store.CIBARequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := hashKey(authReqID)
	rec, ok := s.m[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	if !constantTimeKeyMatch(rec.ID, key) {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	out := cloneCIBARequest(rec)
	out.ID = authReqID
	return out, nil
}

func (s *cibaRequestStore) Approve(_ context.Context, authReqID, subject string) error {
	return s.transition(authReqID, func(rec *store.CIBARequest) error {
		if rec.Status != store.CIBARequestStatusPending {
			return store.ErrConflict
		}
		rec.Status = store.CIBARequestStatusApproved
		rec.Subject = subject
		return nil
	})
}

func (s *cibaRequestStore) Deny(_ context.Context, authReqID, reason string) error {
	return s.transition(authReqID, func(rec *store.CIBARequest) error {
		if rec.Status != store.CIBARequestStatusPending {
			return store.ErrConflict
		}
		rec.Status = store.CIBARequestStatusDenied
		rec.DenyReason = reason
		return nil
	})
}

func (s *cibaRequestStore) RecordPoll(_ context.Context, authReqID string, when time.Time) error {
	return s.transition(authReqID, func(rec *store.CIBARequest) error {
		t := when
		rec.LastPolledAt = &t
		return nil
	})
}

func (s *cibaRequestStore) IncrementPollViolation(_ context.Context, authReqID string) (uint8, error) {
	var violations uint8
	err := s.transition(authReqID, func(rec *store.CIBARequest) error {
		if rec.PollViolations == 255 {
			// Saturate rather than overflow; the poll-abuse gate will
			// already have triggered Deny well before this.
			violations = rec.PollViolations
			return nil
		}
		rec.PollViolations++
		violations = rec.PollViolations
		return nil
	})
	if err != nil {
		return 0, err
	}
	return violations, nil
}

func (s *cibaRequestStore) Consume(_ context.Context, authReqID string) (*store.CIBARequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashKey(authReqID)
	rec, ok := s.m[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	switch rec.Status {
	case store.CIBARequestStatusConsumed:
		return nil, store.ErrAlreadyConsumed
	case store.CIBARequestStatusApproved:
		rec.Status = store.CIBARequestStatusConsumed
		out := cloneCIBARequest(rec)
		out.ID = authReqID
		return out, nil
	default:
		return nil, store.ErrConflict
	}
}

// transition acquires the store mutex and applies mutate to the record
// identified by authReqID. The helper centralises the expiry, lookup,
// and mutex discipline so the public state-change methods stay focused
// on their state-machine rule.
func (s *cibaRequestStore) transition(authReqID string, mutate func(*store.CIBARequest) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashKey(authReqID)
	rec, ok := s.m[key]
	if !ok {
		return store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return store.ErrNotFound
	}
	return mutate(rec)
}

// cloneCIBARequest returns a deep copy of c. Callers may mutate the
// returned record without affecting subsequent reads, and the
// substore's internal state is immune to mutations performed on
// previously returned records.
func cloneCIBARequest(c *store.CIBARequest) *store.CIBARequest {
	if c == nil {
		return nil
	}
	out := *c
	out.Scope = slices.Clone(c.Scope)
	out.Resource = slices.Clone(c.Resource)
	out.ACRValues = slices.Clone(c.ACRValues)
	if c.LastPolledAt != nil {
		t := *c.LastPolledAt
		out.LastPolledAt = &t
	}
	return &out
}
