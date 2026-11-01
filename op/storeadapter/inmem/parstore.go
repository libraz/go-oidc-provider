package inmem

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// --- PushedAuthRequestStore --------------------------------------------------

type parStore struct {
	mu           sync.RWMutex
	clock        Clock
	m            map[string]*store.PushedAuthRequest
	savesSinceGC uint32
}

const (
	// parRetention is how long a PAR record stays in the map past its
	// own ExpiresAt. Consume enforces single-use only — expiry is
	// gated at presentation by Find — so a request_uri whose lifetime
	// (typically 60 seconds) elapsed while the user was working
	// through a password, a second factor and a consent decision is
	// still redeemable at code emission. Reclaiming on expiry alone
	// would make that redemption depend on how many unrelated pushes
	// arrived meanwhile, turning a completed login into a denied one
	// under load.
	//
	// The window therefore has to outlast the whole interaction, whose
	// own record is what bounds an interactive login and defaults to
	// an hour, with room for an embedder that configures a longer one.
	// A day clears every such ceiling by a wide margin and still
	// bounds the map: an unredeemed row is reclaimed rather than held
	// for the process lifetime.
	parRetention = 24 * time.Hour
)

// parReclaimable reports whether a PAR record may be dropped from the
// map. Every reclamation path in this substore — the amortised sweep
// and the key-scoped eviction Save performs — consults this one
// predicate, so no path can retire a row that Consume would still
// redeem. A record without an ExpiresAt opts out of expiry and is
// never reclaimed.
func parReclaimable(rec *store.PushedAuthRequest, now time.Time) bool {
	if rec.ExpiresAt.IsZero() {
		return false
	}
	return patterns.IsExpiredStrict(rec.ExpiresAt.Add(parRetention), now)
}

func newPARStore(c Clock) *parStore {
	return &parStore{clock: c, m: make(map[string]*store.PushedAuthRequest)}
}

func (s *parStore) Save(_ context.Context, par *store.PushedAuthRequest) error {
	if par == nil {
		return errors.New("inmem: nil pushed authorization request")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock.Now()
	key := hashKey(par.URI)
	s.deleteReclaimableKeyLocked(key, now)
	s.maybeGCLocked(now)
	if _, exists := s.m[key]; exists {
		return store.ErrAlreadyExists
	}
	stored := clonePAR(par)
	stored.URI = key
	s.m[key] = stored
	return nil
}

func (s *parStore) Find(_ context.Context, uri string) (*store.PushedAuthRequest, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key := hashKey(uri)
	rec, ok := s.m[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	if !constantTimeKeyMatch(rec.URI, key) {
		return nil, store.ErrNotFound
	}
	if isExpired(rec.ExpiresAt, s.clock) {
		return nil, store.ErrNotFound
	}
	out := clonePAR(rec)
	out.URI = uri
	return out, nil
}

func (s *parStore) Consume(_ context.Context, uri string) (*store.PushedAuthRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hashKey(uri)
	rec, ok := s.m[key]
	if !ok {
		return nil, store.ErrNotFound
	}
	if !constantTimeKeyMatch(rec.URI, key) {
		return nil, store.ErrNotFound
	}
	// Consume enforces single-use only; expiry is gated at presentation
	// by Find (see store.PushedAuthRequestStore.Consume). An interactive
	// login that outlives the request_uri lifetime still redeems here.
	if rec.ConsumedAt != nil {
		return nil, store.ErrAlreadyConsumed
	}
	now := s.clock.Now()
	rec.ConsumedAt = &now
	out := clonePAR(rec)
	out.URI = uri
	return out, nil
}

func clonePAR(p *store.PushedAuthRequest) *store.PushedAuthRequest {
	if p == nil {
		return nil
	}
	out := *p
	out.RawParams = slices.Clone(p.RawParams)
	if p.ConsumedAt != nil {
		t := *p.ConsumedAt
		out.ConsumedAt = &t
	}
	return &out
}

// gcLocked drops every PAR record past [parRetention]. A retained
// record whose ExpiresAt has passed is unreachable through Find but
// still redeemable through Consume, so the sweep waits out the
// retention window before removing it.
func (s *parStore) gcLocked(now time.Time) {
	for key, rec := range s.m {
		if parReclaimable(rec, now) {
			delete(s.m, key)
		}
	}
	s.savesSinceGC = 0
}

func (s *parStore) maybeGCLocked(now time.Time) {
	s.savesSinceGC++
	if !sweepDue(s.savesSinceGC, fullGCInterval, len(s.m)) {
		return
	}
	s.gcLocked(now)
}

// deleteReclaimableKeyLocked evicts the record under key when it is
// past retention, so an insert claiming that key is not rejected as a
// duplicate of a row the store has finished with. A record still
// inside its retention window stays, and the insert reports
// [store.ErrAlreadyExists]: request_uris come from crypto/rand, so a
// collision is a randomness fault, and overwriting a redeemable record
// would hand its holder a different client's pushed request.
func (s *parStore) deleteReclaimableKeyLocked(key string, now time.Time) {
	rec, ok := s.m[key]
	if !ok {
		return
	}
	if parReclaimable(rec, now) {
		delete(s.m, key)
	}
}
