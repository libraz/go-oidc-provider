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
	builder := newGrantClientPageBuilder(cursor, limit)
	for _, rec := range s.m {
		if rec.Subject == subject {
			builder.add(rec.ClientID)
		}
	}
	return builder.page(), nil
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
	builder := newGrantSubjectPageBuilder(cursor, limit)
	for _, rec := range s.m {
		if rec.ClientID == clientID {
			builder.add(rec.Subject)
		}
	}
	return builder.page(), nil
}

// grantClientPageBuilder retains only the lexicographically-smallest limit
// distinct IDs after cursor. Scanning an in-memory map is unavoidable, but
// candidate storage remains O(limit) even when every grant has a unique client.
type grantClientPageBuilder struct {
	cursor    string
	limit     int
	clientIDs []string
	more      bool
	peak      int
}

func newGrantClientPageBuilder(cursor string, limit int) *grantClientPageBuilder {
	return &grantClientPageBuilder{cursor: cursor, limit: limit}
}

func (b *grantClientPageBuilder) add(clientID string) {
	if clientID == "" || clientID <= b.cursor {
		return
	}
	index := sort.SearchStrings(b.clientIDs, clientID)
	if index < len(b.clientIDs) && b.clientIDs[index] == clientID {
		return
	}
	if len(b.clientIDs) < b.limit {
		b.clientIDs = append(b.clientIDs, "")
		copy(b.clientIDs[index+1:], b.clientIDs[index:])
		b.clientIDs[index] = clientID
		b.peak = max(b.peak, len(b.clientIDs))
		return
	}
	b.more = true
	if index == len(b.clientIDs) {
		return
	}
	copy(b.clientIDs[index+1:], b.clientIDs[index:len(b.clientIDs)-1])
	b.clientIDs[index] = clientID
}

func (b *grantClientPageBuilder) page() store.GrantClientPage {
	page := store.GrantClientPage{ClientIDs: b.clientIDs}
	if b.more {
		page.NextCursor = b.clientIDs[len(b.clientIDs)-1]
	}
	return page
}

type grantSubjectPageBuilder struct {
	cursor   string
	limit    int
	subjects []string
	more     bool
}

func newGrantSubjectPageBuilder(cursor string, limit int) *grantSubjectPageBuilder {
	return &grantSubjectPageBuilder{cursor: cursor, limit: limit}
}

func (b *grantSubjectPageBuilder) add(subject string) {
	if subject == "" || subject <= b.cursor {
		return
	}
	index := sort.SearchStrings(b.subjects, subject)
	if index < len(b.subjects) && b.subjects[index] == subject {
		return
	}
	if len(b.subjects) < b.limit {
		b.subjects = append(b.subjects, "")
		copy(b.subjects[index+1:], b.subjects[index:])
		b.subjects[index] = subject
		return
	}
	b.more = true
	if index == len(b.subjects) {
		return
	}
	copy(b.subjects[index+1:], b.subjects[index:len(b.subjects)-1])
	b.subjects[index] = subject
}

func (b *grantSubjectPageBuilder) page() store.GrantSubjectPage {
	page := store.GrantSubjectPage{Subjects: b.subjects}
	if b.more {
		page.NextCursor = b.subjects[len(b.subjects)-1]
	}
	return page
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
