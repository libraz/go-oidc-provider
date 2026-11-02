package inmem

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/op/store"
)

// ssfState is the storage shared by the stream and event substores. One
// mutex guards both so stream deletion drops its queued events
// atomically.
type ssfState struct {
	mu       sync.Mutex
	streams  map[string]*store.SSFStream
	byClient map[string]string // client ID -> stream ID
	events   map[string]*store.SSFEvent
	byStream map[string]map[string]struct{} // stream ID -> JTIs of its queued events
}

func newSSFState() *ssfState {
	return &ssfState{
		streams:  make(map[string]*store.SSFStream),
		byClient: make(map[string]string),
		events:   make(map[string]*store.SSFEvent),
		byStream: make(map[string]map[string]struct{}),
	}
}

// setEvent stores ev under its JTI and indexes it by stream. The caller
// holds mu.
func (st *ssfState) setEvent(ev *store.SSFEvent) {
	st.events[ev.JTI] = ev
	ids := st.byStream[ev.StreamID]
	if ids == nil {
		ids = make(map[string]struct{})
		st.byStream[ev.StreamID] = ids
	}
	ids[ev.JTI] = struct{}{}
}

// deleteEvent removes the event queued under jti and its stream index
// entry. The caller holds mu.
func (st *ssfState) deleteEvent(jti string) {
	ev, ok := st.events[jti]
	if !ok {
		return
	}
	delete(st.events, jti)
	ids := st.byStream[ev.StreamID]
	delete(ids, jti)
	if len(ids) == 0 {
		delete(st.byStream, ev.StreamID)
	}
}

type ssfStreamStore struct{ st *ssfState }

type ssfEventStore struct{ st *ssfState }

// SSFStreams implements [store.SharedSignalsStore].
func (s *Store) SSFStreams() store.SSFStreamStore { return s.ssfStreams }

// SSFEvents implements [store.SharedSignalsStore].
func (s *Store) SSFEvents() store.SSFEventStore { return s.ssfEvents }

var _ store.SharedSignalsStore = (*Store)(nil)

func (s *ssfStreamStore) Create(_ context.Context, in *store.SSFStream) error {
	if in == nil {
		return errors.New("inmem: nil ssf stream")
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	if _, ok := s.st.streams[in.ID]; ok {
		return store.ErrConflict
	}
	if _, ok := s.st.byClient[in.ClientID]; ok {
		return store.ErrConflict
	}
	s.st.streams[in.ID] = cloneSSFStream(in)
	s.st.byClient[in.ClientID] = in.ID
	return nil
}

func (s *ssfStreamStore) Get(_ context.Context, id string) (*store.SSFStream, error) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	rec, ok := s.st.streams[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneSSFStream(rec), nil
}

func (s *ssfStreamStore) GetByClient(_ context.Context, clientID string) (*store.SSFStream, error) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	id, ok := s.st.byClient[clientID]
	if !ok {
		return nil, store.ErrNotFound
	}
	return cloneSSFStream(s.st.streams[id]), nil
}

func (s *ssfStreamStore) ListActive(_ context.Context) ([]*store.SSFStream, error) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	var out []*store.SSFStream
	for _, rec := range s.st.streams {
		if rec.Status == store.SSFStreamEnabled || rec.Status == store.SSFStreamPaused {
			out = append(out, cloneSSFStream(rec))
		}
	}
	return out, nil
}

func (s *ssfStreamStore) Update(_ context.Context, in *store.SSFStream, notice *store.SSFEvent) error {
	if in == nil {
		return errors.New("inmem: nil ssf stream")
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	cur, ok := s.st.streams[in.ID]
	if !ok {
		return store.ErrNotFound
	}
	if notice != nil {
		if _, dup := s.st.events[notice.JTI]; dup {
			return store.ErrAlreadyExists
		}
	}
	next := cloneSSFStream(in)
	next.ClientID = cur.ClientID
	s.st.streams[in.ID] = next
	for jti := range s.st.byStream[in.ID] {
		ev := s.st.events[jti]
		ev.Delivery = next.Delivery.Method
		if ev.Kind != store.SSFEventKindEvent {
			continue
		}
		if next.Status == store.SSFStreamDisabled {
			s.st.deleteEvent(jti)
			continue
		}
		ev.Held = next.Status == store.SSFStreamPaused
	}
	if notice != nil {
		s.st.putEvent(notice)
	}
	return nil
}

func (s *ssfStreamStore) Delete(_ context.Context, id string) error {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	rec, ok := s.st.streams[id]
	if !ok {
		return store.ErrNotFound
	}
	delete(s.st.streams, id)
	delete(s.st.byClient, rec.ClientID)
	for jti := range s.st.byStream[id] {
		s.st.deleteEvent(jti)
	}
	return nil
}

func (s *ssfEventStore) Enqueue(_ context.Context, in *store.SSFEvent) error {
	if in == nil {
		return errors.New("inmem: nil ssf event")
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	if _, ok := s.st.events[in.JTI]; ok {
		return store.ErrAlreadyExists
	}
	if st, ok := s.st.streams[in.StreamID]; ok && !ssfEventMatchesStream(in, st) {
		return store.ErrConflict
	}
	s.st.putEvent(in)
	return nil
}

// putEvent stores a copy of in, first dropping the stream's queued event
// of the same control Kind. The caller holds mu.
func (st *ssfState) putEvent(in *store.SSFEvent) {
	if in.Kind != store.SSFEventKindEvent {
		for jti := range st.byStream[in.StreamID] {
			if st.events[jti].Kind == in.Kind {
				st.deleteEvent(jti)
			}
		}
	}
	st.setEvent(cloneSSFEvent(in))
}

// ssfEventMatchesStream reports whether ev carries the tags s's current
// state gives a newly queued event.
func ssfEventMatchesStream(ev *store.SSFEvent, s *store.SSFStream) bool {
	if ev.Delivery != s.Delivery.Method {
		return false
	}
	if ev.Kind != store.SSFEventKindEvent {
		return true
	}
	return s.Status != store.SSFStreamDisabled && ev.Held == (s.Status == store.SSFStreamPaused)
}

func (s *ssfEventStore) ClaimDue(_ context.Context, now time.Time, n, perStream int, lease time.Duration) ([]*store.SSFEvent, error) {
	if n <= 0 || perStream <= 0 {
		return nil, errors.New("inmem: ssf claim sizes must be positive")
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	byDueOrder := func(a, b *store.SSFEvent) int {
		return cmp.Or(a.NextAttemptAt.Compare(b.NextAttemptAt), cmp.Compare(a.JTI, b.JTI))
	}
	// Only a stream's first perStream due events can ever be claimed, so
	// each stream contributes at most that many candidates.
	var candidates []*store.SSFEvent
	for _, jtis := range s.st.byStream {
		var due []*store.SSFEvent
		for jti := range jtis {
			if ev := s.st.events[jti]; ev.Delivery == store.SSFDeliveryPush && !ev.Held && !ev.NextAttemptAt.After(now) {
				due = append(due, ev)
			}
		}
		slices.SortFunc(due, byDueOrder)
		candidates = append(candidates, due[:min(perStream, len(due))]...)
	}
	slices.SortFunc(candidates, byDueOrder)
	out := make([]*store.SSFEvent, 0, min(n, len(candidates)))
	for _, ev := range candidates[:min(n, len(candidates))] {
		ev.NextAttemptAt = now.Add(lease)
		out = append(out, cloneSSFEvent(ev))
	}
	return out, nil
}

func (s *ssfEventStore) Reschedule(_ context.Context, jti string, next time.Time, attempts int) error {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	ev, ok := s.st.events[jti]
	if !ok {
		return store.ErrNotFound
	}
	ev.NextAttemptAt = next
	ev.Attempts = attempts
	return nil
}

func (s *ssfEventStore) Ack(_ context.Context, streamID string, jtis []string) error {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	for _, jti := range jtis {
		if ev, ok := s.st.events[jti]; ok && ev.StreamID == streamID {
			s.st.deleteEvent(jti)
		}
	}
	return nil
}

func (s *ssfEventStore) Pending(_ context.Context, streamID string, n int) ([]*store.SSFEvent, bool, error) {
	if n <= 0 {
		return nil, false, errors.New("inmem: ssf pending size must be positive")
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	var queued []*store.SSFEvent
	for jti := range s.st.byStream[streamID] {
		if ev := s.st.events[jti]; ev.Delivery == store.SSFDeliveryPoll && !ev.Held {
			queued = append(queued, ev)
		}
	}
	slices.SortFunc(queued, func(a, b *store.SSFEvent) int { return strings.Compare(a.JTI, b.JTI) })
	more := len(queued) > n
	if more {
		queued = queued[:n]
	}
	var out []*store.SSFEvent
	for _, ev := range queued {
		out = append(out, cloneSSFEvent(ev))
	}
	return out, more, nil
}

func (s *ssfEventStore) DeleteExpired(_ context.Context, now time.Time) (int, error) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	n := 0
	for jti, ev := range s.st.events {
		if !ev.ExpiresAt.After(now) {
			s.st.deleteEvent(jti)
			n++
		}
	}
	return n, nil
}

func cloneSSFStream(s *store.SSFStream) *store.SSFStream {
	out := *s
	out.Delivery.SealedAuthorizationHeader = slices.Clone(s.Delivery.SealedAuthorizationHeader)
	out.EventsRequested = slices.Clone(s.EventsRequested)
	out.EventsDelivered = slices.Clone(s.EventsDelivered)
	return &out
}

func cloneSSFEvent(e *store.SSFEvent) *store.SSFEvent {
	out := *e
	out.Claims = slices.Clone(e.Claims)
	return &out
}
