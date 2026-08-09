package inmem

import (
	"context"
	"errors"
	"math"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// authnLockoutStore is the in-memory reference implementation of
// [store.AuthnLockoutStore]. It mirrors the contract used by the other
// inmem substores: every Get clones the record so callers may mutate it
// freely, and every successful CompareAndSwap clones the supplied pointer
// so a later mutation by the caller does not leak into the map.
//
// The version comparison and replacement happen while holding the
// same mutex. This makes every lockout transition atomic, including
// races between failure increments, window rollover, and success
// reset.
type authnLockoutStore struct {
	mu           sync.Mutex
	clock        Clock
	m            map[string]*store.AuthnLockoutRecord
	swapsSinceGC uint32
}

const (
	// authnLockoutFullGCSwapInterval is how many successful swaps pass
	// between full sweeps of the counter map. The map is keyed by
	// subject, and an attacker probing a large list of guessed
	// usernames mints one row per guess, so it needs reclamation.
	authnLockoutFullGCSwapInterval uint32 = 64

	// authnLockoutRetention is how long a counter is kept after it has
	// stopped influencing any authentication decision. A record is
	// reclaimable once its LockedUntil stamp has passed and its
	// FirstFailureAt anchor is older than this window: from that point
	// on the library's own rolling-window rollover resets the counter
	// on the next failure, so dropping the row and keeping it are the
	// same observable outcome. The value deliberately exceeds the
	// longest rolling window and the longest lock the library applies,
	// so neither clock skew nor a future threshold change can make the
	// sweep discard a counter that still bounds an attacker's budget.
	authnLockoutRetention = 48 * time.Hour
)

func newAuthnLockoutStore(c Clock) *authnLockoutStore {
	return &authnLockoutStore{clock: c, m: make(map[string]*store.AuthnLockoutRecord)}
}

// Get implements [store.AuthnLockoutStore].
func (s *authnLockoutStore) Get(ctx context.Context, subject string) (*store.AuthnLockoutRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.m[subject]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneAuthnLockoutRecord(rec), nil
}

// CompareAndSwap implements [store.AuthnLockoutStore].
func (s *authnLockoutStore) CompareAndSwap(ctx context.Context, expectedVersion uint64, next *store.AuthnLockoutRecord) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if next == nil {
		return false, errors.New("inmem: nil authn lockout record")
	}
	if next.Subject == "" {
		return false, errors.New("inmem: authn lockout record missing Subject")
	}
	if expectedVersion == math.MaxUint64 {
		return false, errors.New("inmem: authn lockout version overflow")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	current, ok := s.m[next.Subject]
	if !ok {
		if expectedVersion != 0 {
			return false, nil
		}
	} else if expectedVersion == 0 || current.Version != expectedVersion {
		return false, nil
	}

	persisted := cloneAuthnLockoutRecord(next)
	persisted.Version = expectedVersion + 1
	s.m[next.Subject] = persisted
	s.maybeGCLocked(s.clock.Now(), next.Subject)
	return true, nil
}

// maybeGCLocked runs a full sweep once every
// [authnLockoutFullGCSwapInterval] successful swaps. It runs after the
// swap has been applied and skips the subject just written so a
// caller's own transition can never be undone by the sweep it
// triggered; every other reclaimable row is dropped.
func (s *authnLockoutStore) maybeGCLocked(now time.Time, keep string) {
	s.swapsSinceGC++
	if s.swapsSinceGC < authnLockoutFullGCSwapInterval {
		return
	}
	s.swapsSinceGC = 0
	for subject, rec := range s.m {
		if subject == keep {
			continue
		}
		if authnLockoutReclaimable(rec, now) {
			delete(s.m, subject)
		}
	}
}

// authnLockoutReclaimable reports whether rec has stopped bounding any
// authentication attempt: the lock it carries has expired and its
// window anchor is older than [authnLockoutRetention]. A record whose
// anchor is unset carries no failures at all and is reclaimable as soon
// as it is not locked.
func authnLockoutReclaimable(rec *store.AuthnLockoutRecord, now time.Time) bool {
	if !rec.LockedUntil.IsZero() && !now.After(rec.LockedUntil) {
		return false
	}
	if rec.FirstFailureAt.IsZero() {
		return true
	}
	return now.Sub(rec.FirstFailureAt) > authnLockoutRetention
}

func cloneAuthnLockoutRecord(r *store.AuthnLockoutRecord) *store.AuthnLockoutRecord {
	if r == nil {
		return nil
	}
	out := *r
	return &out
}
