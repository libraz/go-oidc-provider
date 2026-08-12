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
	mu           sync.RWMutex
	clock        Clock
	m            map[string]*store.CIBARequest // key: hashKey(auth_req_id)
	savesSinceGC uint32
}

// cibaFullGCSaveInterval is how many Save calls pass between full
// sweeps of the CIBA map. Save additionally evicts the exact key it is
// about to write whenever that key holds an expired record, so a
// colliding auth_req_id is reclaimed immediately rather than waiting
// for the sweep.
const cibaFullGCSaveInterval uint32 = 64

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
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	key := hashKey(req.ID)
	s.deleteExpiredKeyLocked(key, now)
	s.maybeGCLocked(now)
	if _, exists := s.m[key]; exists {
		return store.ErrAlreadyExists
	}
	stored := cloneCIBARequest(req)
	if stored.Status == 0 {
		// Caller forgot to stamp the status; default the stored copy
		// to Pending without mutating the caller-owned struct.
		stored.Status = store.CIBARequestStatusPending
	}
	stored.ID = key
	s.m[key] = stored
	return nil
}

func (s *cibaRequestStore) gcLocked(now time.Time) {
	for key, rec := range s.m {
		if isExpiredAtStrict(rec.ExpiresAt, now) {
			delete(s.m, key)
		}
	}
	s.savesSinceGC = 0
}

// maybeGCLocked runs a full sweep once every [cibaFullGCSaveInterval]
// saves, amortising the sweep over the saves that made it necessary
// instead of paying O(total requests) on each one.
func (s *cibaRequestStore) maybeGCLocked(now time.Time) {
	s.savesSinceGC++
	if s.savesSinceGC < cibaFullGCSaveInterval {
		return
	}
	s.gcLocked(now)
}

// deleteExpiredKeyLocked evicts the record stored under key when it has
// expired. Save calls it so an incoming auth_req_id that collides with
// a dead record is accepted rather than rejected as a duplicate; the
// amortised sweep alone would leave that collision standing for up to
// [cibaFullGCSaveInterval] saves.
func (s *cibaRequestStore) deleteExpiredKeyLocked(key string, now time.Time) {
	rec, ok := s.m[key]
	if !ok {
		return
	}
	if isExpiredAtStrict(rec.ExpiresAt, now) {
		delete(s.m, key)
	}
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

func (s *cibaRequestStore) Approve(_ context.Context, authReqID, subject, acr string, authTime time.Time) error {
	return s.transition(authReqID, func(rec *store.CIBARequest) error {
		if rec.Subject != "" && rec.Subject != subject {
			return store.ErrConflict
		}
		if rec.Status != store.CIBARequestStatusPending {
			return store.ErrConflict
		}
		rec.Status = store.CIBARequestStatusApproved
		rec.Subject = subject
		rec.ACR = acr
		rec.AuthTime = authTime
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

func (s *cibaRequestStore) RecordPoll(_ context.Context, authReqID string, when time.Time, nextInterval time.Duration) error {
	return s.transition(authReqID, func(rec *store.CIBARequest) error {
		t := when
		rec.LastPolledAt = &t
		if nextInterval > rec.Interval {
			rec.Interval = nextInterval
		}
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
