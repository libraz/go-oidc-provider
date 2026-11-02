package inmem

import (
	"context"
	"errors"
	"slices"
	"sort"
	"sync"

	"github.com/libraz/go-oidc-provider/op/store"
)

// --- GrantStore --------------------------------------------------------------

type grantStore struct {
	mu sync.RWMutex
	m  map[string]*store.Grant
}

func newGrantStore() *grantStore {
	return &grantStore{m: make(map[string]*store.Grant)}
}

func (s *grantStore) Save(_ context.Context, g *store.Grant) error {
	if g == nil {
		return errors.New("inmem: nil grant")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[g.ID] = cloneGrant(g)
	return nil
}

func (s *grantStore) Find(_ context.Context, id string) (*store.Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.m[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneGrant(rec), nil
}

func (s *grantStore) FindBySubjectClient(_ context.Context, subject, clientID string) (*store.Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var best *store.Grant
	for _, rec := range s.m {
		if rec.Subject != subject || rec.ClientID != clientID {
			continue
		}
		if best == nil || rec.UpdatedAt.After(best.UpdatedAt) {
			best = rec
		}
	}
	if best == nil {
		return nil, store.ErrNotFound
	}
	return cloneGrant(best), nil
}

// ListBySubject enumerates every grant the subject currently holds.
// The implementation walks the in-memory map and returns clones so the
// caller can mutate the slice without racing the store. Unlike
// FindBySubjectClient, it intentionally does not collapse duplicate
// (subject, clientID) rows: callers that revoke by listing must see
// every active grant so no orphaned token chain survives.
func (s *grantStore) ListBySubject(_ context.Context, subject string) ([]*store.Grant, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*store.Grant, 0)
	for _, rec := range s.m {
		if rec.Subject != subject {
			continue
		}
		out = append(out, cloneGrant(rec))
	}
	return out, nil
}

func (s *grantStore) ListClientIDsBySubject(
	ctx context.Context,
	subject, cursor string,
	limit int,
) (store.GrantClientPage, error) {
	if err := ctx.Err(); err != nil {
		return store.GrantClientPage{}, err
	}
	if limit <= 0 {
		return store.GrantClientPage{}, errors.New("inmem: grant client page limit must be positive")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	builder := newSortedPageBuilder(cursor, limit)
	for _, rec := range s.m {
		if rec.Subject == subject {
			builder.add(rec.ClientID)
		}
	}
	return builder.clientPage(), nil
}

// ListSubjectsByClient implements [store.GrantSubjectLister]. The map scan
// is unavoidable for the in-memory reference backend, but the builder keeps
// only the lexicographically-smallest limit distinct subjects after cursor.
// Deleted grants are removed from the map by RevokeByClient, so revoked
// consent never leaks through this audience-oriented view.
func (s *grantStore) ListSubjectsByClient(
	ctx context.Context,
	clientID, cursor string,
	limit int,
) (store.GrantSubjectPage, error) {
	if err := ctx.Err(); err != nil {
		return store.GrantSubjectPage{}, err
	}
	if limit <= 0 {
		return store.GrantSubjectPage{}, errors.New("inmem: grant subject page limit must be positive")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	builder := newSortedPageBuilder(cursor, limit)
	for _, rec := range s.m {
		if rec.ClientID == clientID {
			builder.add(rec.Subject)
		}
	}
	return builder.subjectPage(), nil
}

// sortedPageBuilder retains only the lexicographically-smallest limit
// distinct values after cursor. Scanning an in-memory map is unavoidable, but
// candidate storage remains O(limit) even when every grant has a unique value.
type sortedPageBuilder struct {
	cursor string
	limit  int
	items  []string
	more   bool
	peak   int
}

func newSortedPageBuilder(cursor string, limit int) *sortedPageBuilder {
	return &sortedPageBuilder{cursor: cursor, limit: limit}
}

func (b *sortedPageBuilder) add(value string) {
	if value == "" || value <= b.cursor {
		return
	}
	index := sort.SearchStrings(b.items, value)
	if index < len(b.items) && b.items[index] == value {
		return
	}
	if len(b.items) < b.limit {
		b.items = append(b.items, "")
		copy(b.items[index+1:], b.items[index:])
		b.items[index] = value
		b.peak = max(b.peak, len(b.items))
		return
	}
	b.more = true
	if index == len(b.items) {
		return
	}
	copy(b.items[index+1:], b.items[index:len(b.items)-1])
	b.items[index] = value
}

// result returns the retained values and, when more remain, the cursor for
// the next page.
func (b *sortedPageBuilder) result() (items []string, nextCursor string) {
	if b.more {
		nextCursor = b.items[len(b.items)-1]
	}
	return b.items, nextCursor
}

func (b *sortedPageBuilder) clientPage() store.GrantClientPage {
	items, next := b.result()
	return store.GrantClientPage{ClientIDs: items, NextCursor: next}
}

func (b *sortedPageBuilder) subjectPage() store.GrantSubjectPage {
	items, next := b.result()
	return store.GrantSubjectPage{Subjects: items, NextCursor: next}
}

func (s *grantStore) HasAny(_ context.Context) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.m) > 0, nil
}

func (s *grantStore) Delete(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.m[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.m, id)
	return nil
}

// RevokeByClient implements [store.RevokeByClient]. The dynamic
// registration cascade calls it so a deleted client takes its
// outstanding grants with it. A non-existent client is a no-op.
func (s *grantStore) RevokeByClient(_ context.Context, clientID string) error {
	if clientID == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, rec := range s.m {
		if rec.ClientID == clientID {
			delete(s.m, id)
		}
	}
	return nil
}

func cloneGrant(g *store.Grant) *store.Grant {
	if g == nil {
		return nil
	}
	out := *g
	out.Scope = slices.Clone(g.Scope)
	out.Claims = cloneMap(g.Claims)
	out.AMR = slices.Clone(g.AMR)
	out.AuthorizationDetails = cloneObjectArray(g.AuthorizationDetails)
	return &out
}
