package inmem

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// deviceCodeStore is the in-memory implementation of
// [store.DeviceCodeStore]. The primary map is keyed on the SHA-256
// digest of the wire device_code so a heap dump cannot reconstruct
// the bearer secret; a secondary index maps canonical user_code
// strings to the same digest so FindByUserCode runs in O(1) without
// scanning the primary map.
type deviceCodeStore struct {
	mu            sync.RWMutex
	clock         Clock
	m             map[string]*store.DeviceCode // key: hashKey(deviceCode)
	userCodeIndex map[string]string            // key: canonical user_code, value: hashKey(deviceCode)
}

func newDeviceCodeStore(c Clock) *deviceCodeStore {
	return &deviceCodeStore{
		clock:         c,
		m:             make(map[string]*store.DeviceCode),
		userCodeIndex: make(map[string]string),
	}
}

func (s *deviceCodeStore) Save(_ context.Context, code *store.DeviceCode) error {
	if code == nil {
		return errors.New("inmem: nil device code")
	}
	if code.Status == 0 {
		// Caller forgot to stamp the status; default to Pending so
		// the lifecycle starts from a known state.
		code.Status = store.DeviceCodeStatusPending
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashKey(code.ID)
	if _, exists := s.m[key]; exists {
		return store.ErrAlreadyExists
	}
	if _, taken := s.userCodeIndex[code.UserCode]; taken {
		return store.ErrAlreadyExists
	}
	stored := cloneDeviceCode(code)
	stored.ID = key
	s.m[key] = stored
	s.userCodeIndex[code.UserCode] = key
	return nil
}

func (s *deviceCodeStore) FindByDeviceCode(_ context.Context, deviceCode string) (*store.DeviceCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := hashKey(deviceCode)
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
	out := cloneDeviceCode(rec)
	out.ID = deviceCode
	return out, nil
}

func (s *deviceCodeStore) FindByUserCode(_ context.Context, userCode string) (*store.DeviceCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.userCodeIndex[userCode]
	if !ok {
		return nil, store.ErrNotFound
	}
	rec, ok := s.m[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	// The user_code path does not return the wire device_code: the
	// verification page only needs the metadata, and exposing the
	// device_code through this lookup would let a malicious page
	// poll on the device's behalf. Callers that legitimately need
	// the device_code (none in v0.9.1) can call FindByDeviceCode
	// once they have it.
	out := cloneDeviceCode(rec)
	out.ID = ""
	return out, nil
}

func (s *deviceCodeStore) Approve(_ context.Context, deviceCode, subject string, authTime time.Time) error {
	return s.transition(deviceCode, func(rec *store.DeviceCode) error {
		if rec.Status != store.DeviceCodeStatusPending {
			return store.ErrConflict
		}
		rec.Status = store.DeviceCodeStatusApproved
		rec.Subject = subject
		rec.AuthTime = authTime
		return nil
	})
}

func (s *deviceCodeStore) Deny(_ context.Context, deviceCode, reason string) error {
	return s.transition(deviceCode, func(rec *store.DeviceCode) error {
		if rec.Status != store.DeviceCodeStatusPending {
			return store.ErrConflict
		}
		rec.Status = store.DeviceCodeStatusDenied
		rec.DenyReason = reason
		return nil
	})
}

func (s *deviceCodeStore) RecordPoll(_ context.Context, deviceCode string, when time.Time, nextInterval time.Duration) error {
	return s.transition(deviceCode, func(rec *store.DeviceCode) error {
		t := when
		rec.LastPolledAt = &t
		// Only escalate the bar; the library passes the existing
		// Interval verbatim on non-slow_down decisions, so a value
		// that does not raise the gate is intentionally a no-op on
		// the Interval field. The atomic update of both fields under
		// the same mutex is the contract concurrent pollers rely on
		// (RFC 8628 §3.5).
		if nextInterval > rec.Interval {
			rec.Interval = nextInterval
		}
		return nil
	})
}

func (s *deviceCodeStore) IncrementUserCodeStrike(_ context.Context, deviceCode string) (uint8, error) {
	var strikes uint8
	err := s.transition(deviceCode, func(rec *store.DeviceCode) error {
		if rec.UserCodeStrikes == 255 {
			// Saturate rather than overflow; the brute-force gate
			// will already have triggered Deny well before this.
			strikes = rec.UserCodeStrikes
			return nil
		}
		rec.UserCodeStrikes++
		strikes = rec.UserCodeStrikes
		return nil
	})
	if err != nil {
		return 0, err
	}
	return strikes, nil
}

func (s *deviceCodeStore) IncrementPollViolation(_ context.Context, deviceCode string) (uint8, error) {
	var violations uint8
	err := s.transition(deviceCode, func(rec *store.DeviceCode) error {
		if rec.PollViolations == 255 {
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

func (s *deviceCodeStore) Consume(_ context.Context, deviceCode string) (*store.DeviceCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashKey(deviceCode)
	rec, ok := s.m[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	switch rec.Status {
	case store.DeviceCodeStatusConsumed:
		return nil, store.ErrAlreadyConsumed
	case store.DeviceCodeStatusApproved:
		rec.Status = store.DeviceCodeStatusConsumed
		out := cloneDeviceCode(rec)
		out.ID = deviceCode
		return out, nil
	default:
		return nil, store.ErrConflict
	}
}

// transition acquires the store mutex and applies mutate to the
// record identified by deviceCode. The helper centralises the
// expiry, lookup, and mutex discipline so the public state-change
// methods stay focused on their state-machine rule.
func (s *deviceCodeStore) transition(deviceCode string, mutate func(*store.DeviceCode) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashKey(deviceCode)
	rec, ok := s.m[key]
	if !ok {
		return store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return store.ErrNotFound
	}
	return mutate(rec)
}

// cloneDeviceCode returns a deep copy of c. Callers may mutate the
// returned record without affecting subsequent reads, and the
// substore's internal state is immune to mutations performed on
// previously returned records.
func cloneDeviceCode(c *store.DeviceCode) *store.DeviceCode {
	if c == nil {
		return nil
	}
	out := *c
	out.Scope = slices.Clone(c.Scope)
	out.Resource = slices.Clone(c.Resource)
	if c.LastPolledAt != nil {
		t := *c.LastPolledAt
		out.LastPolledAt = &t
	}
	return &out
}
