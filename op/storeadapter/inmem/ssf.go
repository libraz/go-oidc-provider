package inmem

import (
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
}

func newSSFState() *ssfState {
	return &ssfState{
		streams:  make(map[string]*store.SSFStream),
		byClient: make(map[string]string),
		events:   make(map[string]*store.SSFEvent),
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

func (s *ssfStreamStore) Update(_ context.Context, in *store.SSFStream) error {
	if in == nil {
		return errors.New("inmem: nil ssf stream")
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	cur, ok := s.st.streams[in.ID]
	if !ok {
		return store.ErrNotFound
	}
	next := cloneSSFStream(in)
	next.ClientID = cur.ClientID
	s.st.streams[in.ID] = next
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
	for jti, ev := range s.st.events {
		if ev.StreamID == id {
			delete(s.st.events, jti)
		}
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
	if in.Kind == store.SSFEventKindVerification {
		for jti, ev := range s.st.events {
			if ev.StreamID == in.StreamID && ev.Kind == store.SSFEventKindVerification {
				delete(s.st.events, jti)
			}
		}
	}
	s.st.events[in.JTI] = cloneSSFEvent(in)
	return nil
}

func (s *ssfEventStore) ClaimDue(_ context.Context, now time.Time, n int, lease time.Duration) ([]*store.SSFEvent, error) {
	if n <= 0 {
		return nil, errors.New("inmem: ssf claim size must be positive")
	}
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	var due []*store.SSFEvent
	for _, ev := range s.st.events {
		if ev.Delivery == store.SSFDeliveryPush && !ev.Held && !ev.NextAttemptAt.After(now) {
			due = append(due, ev)
		}
	}
	slices.SortFunc(due, func(a, b *store.SSFEvent) int {
		if c := a.NextAttemptAt.Compare(b.NextAttemptAt); c != 0 {
			return c
		}
		if a.JTI < b.JTI {
			return -1
		}
		if a.JTI > b.JTI {
			return 1
		}
		return 0
	})
	if len(due) > n {
		due = due[:n]
	}
	out := make([]*store.SSFEvent, 0, len(due))
	for _, ev := range due {
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
			delete(s.st.events, jti)
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
	for _, ev := range s.st.events {
		if ev.StreamID == streamID && ev.Delivery == store.SSFDeliveryPoll && !ev.Held {
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

func (s *ssfEventStore) Retag(_ context.Context, streamID string, delivery store.SSFDeliveryMethod, held bool) error {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	for _, ev := range s.st.events {
		if ev.StreamID != streamID {
			continue
		}
		ev.Delivery = delivery
		if ev.Kind == store.SSFEventKindEvent {
			ev.Held = held
		}
	}
	return nil
}

func (s *ssfEventStore) Purge(_ context.Context, streamID string, includeControl bool) error {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	for jti, ev := range s.st.events {
		if ev.StreamID == streamID && (includeControl || ev.Kind == store.SSFEventKindEvent) {
			delete(s.st.events, jti)
		}
	}
	return nil
}

func (s *ssfEventStore) DeleteExpired(_ context.Context, now time.Time) (int, error) {
	s.st.mu.Lock()
	defer s.st.mu.Unlock()
	n := 0
	for jti, ev := range s.st.events {
		if !ev.ExpiresAt.After(now) {
			delete(s.st.events, jti)
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
