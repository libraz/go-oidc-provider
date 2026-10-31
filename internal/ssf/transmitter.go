package ssf

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// maxFanOut caps the receivers one Publish resolves (one grant page), so
// the synchronous logout path stays bounded.
const maxFanOut = 256

// eventTTL is how long a queued SET waits before DeleteExpired drops it.
const eventTTL = 7 * 24 * time.Hour

const (
	eventEnqueued      = string(auditevent.AuditSSFSETEnqueued)
	eventEnqueueFailed = string(auditevent.AuditSSFEnqueueFailed)
)

// enqueue_failed reasons.
const (
	reasonFanoutCapacity = "fanout_capacity"
	reasonGrantLookup    = "grant_lookup"
	reasonStreamList     = "stream_list"
	reasonClientLookup   = "client_lookup"
	reasonProjection     = "subject_projection"
	reasonClaims         = "claims"
	reasonEnqueue        = "enqueue"
)

// Deps are the construction-time dependencies of a [Transmitter].
type Deps struct {
	// Issuer is the OP issuer stamped on iss and on iss_sub. Required.
	Issuer string

	// Streams and Events are the SSF substores. Required.
	Streams store.SSFStreamStore
	Events  store.SSFEventStore

	// Grants resolves which clients hold a grant for a subject. Required.
	Grants store.GrantClientLister

	// Clients resolves each receiver for subject projection. Required.
	Clients store.ClientStore

	// SubjectProjector converts the OP-internal subject into the
	// receiver-facing one (pairwise aware). Nil keeps the raw subject.
	SubjectProjector func(ctx context.Context, raw string, client *store.Client) (string, error)

	// Audit receives ssf.set.enqueued / ssf.enqueue_failed. Nil discards.
	Audit audit.Emitter

	// Clock stamps iat, event_timestamp and the queue times. Nil is the
	// system clock.
	Clock timex.Clock
}

// Transmitter turns security events into queued SET claims. Safe for
// concurrent use.
type Transmitter struct {
	issuer    string
	streams   store.SSFStreamStore
	events    store.SSFEventStore
	grants    store.GrantClientLister
	clients   store.ClientStore
	projector func(ctx context.Context, raw string, client *store.Client) (string, error)
	audit     audit.Emitter
	clock     timex.Clock
}

// New builds a Transmitter.
func New(d Deps) (*Transmitter, error) {
	switch {
	case d.Issuer == "":
		return nil, errors.New("ssf: Deps.Issuer is empty")
	case d.Streams == nil, d.Events == nil:
		return nil, errors.New("ssf: Deps.Streams and Deps.Events are required")
	case d.Grants == nil:
		return nil, errors.New("ssf: Deps.Grants is required")
	case d.Clients == nil:
		return nil, errors.New("ssf: Deps.Clients is required")
	}
	emitter := d.Audit
	if emitter == nil {
		emitter = audit.Discard()
	}
	return &Transmitter{
		issuer:    d.Issuer,
		streams:   d.Streams,
		events:    d.Events,
		grants:    d.Grants,
		clients:   d.Clients,
		projector: d.SubjectProjector,
		audit:     emitter,
		clock:     timex.OrSystem(d.Clock),
	}, nil
}

// Publish enqueues one SET of event type et about subject for every
// active stream whose receiver holds a grant for the subject and whose
// events_delivered includes et. It costs two reads (grant page, active
// streams) plus one client read and one enqueue per match.
//
// A paused stream receives the SET held; a disabled one receives
// nothing. Per-receiver failures are audited as ssf.enqueue_failed and
// joined into the returned error after every other receiver has been
// served. A grant page past the fan-out cap is served up to the cap and
// the remainder is audited with reason fanout_capacity. It returns the
// number of SETs enqueued.
func (t *Transmitter) Publish(ctx context.Context, et EventType, subject string, f Fields) (int, error) {
	if subject == "" {
		return 0, fmt.Errorf("%w: empty subject", ErrInvalidEvent)
	}
	if !isOrdinary(et) {
		return 0, fmt.Errorf("%w: %q is not an ordinary event type", ErrInvalidEvent, et)
	}
	now := t.clock.Now()
	payload, err := eventPayload(et, f, now)
	if err != nil {
		return 0, err
	}
	targets, err := t.targets(ctx, et, subject)
	if err != nil || len(targets) == 0 {
		return 0, err
	}
	txn, err := NewID()
	if err != nil {
		return 0, err
	}
	var (
		n      int
		faults []error
	)
	for _, s := range targets {
		held := s.Status == store.SSFStreamPaused
		sent, err := t.publishTo(ctx, s, et, subject, txn, payload, held, now)
		if err != nil {
			faults = append(faults, err)
			continue
		}
		if sent {
			n++
		}
	}
	return n, errors.Join(faults...)
}

// targets returns the enabled or paused streams, in grant-page order,
// whose receiver holds a grant for subject and that deliver et.
func (t *Transmitter) targets(ctx context.Context, et EventType, subject string) ([]*store.SSFStream, error) {
	page, err := t.grants.ListClientIDsBySubject(ctx, subject, "", maxFanOut)
	if err != nil {
		t.emitFailed(ctx, et, "", "", reasonGrantLookup, err)
		return nil, fmt.Errorf("ssf: list clients for subject: %w", err)
	}
	if page.NextCursor != "" {
		t.emitFailed(ctx, et, "", "", reasonFanoutCapacity,
			fmt.Errorf("subject has grants for more than %d clients", maxFanOut))
	}
	if len(page.ClientIDs) == 0 {
		return nil, nil
	}
	active, err := t.streams.ListActive(ctx)
	if err != nil {
		t.emitFailed(ctx, et, "", "", reasonStreamList, err)
		return nil, fmt.Errorf("ssf: list active streams: %w", err)
	}
	byClient := make(map[string]*store.SSFStream, len(active))
	for _, s := range active {
		live := s.Status == store.SSFStreamEnabled || s.Status == store.SSFStreamPaused
		if live && slices.Contains(s.EventsDelivered, string(et)) {
			byClient[s.ClientID] = s
		}
	}
	out := make([]*store.SSFStream, 0, len(byClient))
	for _, clientID := range page.ClientIDs {
		if s, ok := byClient[clientID]; ok {
			out = append(out, s)
		}
	}
	return out, nil
}

// publishTo builds and enqueues one ordinary SET for stream s. It
// reports false without error when the receiver client no longer exists.
func (t *Transmitter) publishTo(
	ctx context.Context,
	s *store.SSFStream,
	et EventType,
	subject, txn string,
	payload map[string]any,
	held bool,
	now time.Time,
) (bool, error) {
	client, err := t.clients.GetClient(ctx, s.ClientID)
	if errors.Is(err, store.ErrNotFound) {
		// A stale grant or stream for a deleted client has no receiver.
		return false, nil
	}
	if err != nil {
		t.emitFailed(ctx, et, s.ClientID, s.ID, reasonClientLookup, err)
		return false, fmt.Errorf("ssf: client %q: %w", s.ClientID, err)
	}
	sub := subject
	if t.projector != nil {
		sub, err = t.projector(ctx, subject, client)
		if err == nil && sub == "" {
			err = errors.New("subject projector returned an empty subject")
		}
		if err != nil {
			t.emitFailed(ctx, et, s.ClientID, s.ID, reasonProjection, err)
			return false, fmt.Errorf("ssf: project subject for client %q: %w", s.ClientID, err)
		}
	}
	if _, err := t.enqueue(ctx, s, et, store.SSFEventKindEvent, held, IssSubSubject(t.issuer, sub), txn, payload, now); err != nil {
		return false, err
	}
	return true, nil
}

// EnqueueControl enqueues a stream-updated or verification SET for s.
// Control events are never held and are queued whatever the stream's
// status; a verification replaces the stream's pending one. It returns
// the queued event's jti.
func (t *Transmitter) EnqueueControl(ctx context.Context, s *store.SSFStream, et EventType, f ControlFields) (string, error) {
	if s == nil {
		return "", errors.New("ssf: nil stream")
	}
	payload, err := controlPayload(et, f)
	if err != nil {
		return "", err
	}
	now := t.clock.Now()
	return t.enqueue(ctx, s, et, controlKind(et), false, StreamSubject(s.ID), "", payload, now)
}

// enqueue builds and stores one SET for s under a fresh jti and returns
// the jti.
func (t *Transmitter) enqueue(
	ctx context.Context,
	s *store.SSFStream,
	et EventType,
	kind store.SSFEventKind,
	held bool,
	subID map[string]string,
	txn string,
	payload map[string]any,
	now time.Time,
) (string, error) {
	jti, err := NewID()
	if err != nil {
		return "", err
	}
	claims, err := BuildClaims(Claims{
		Issuer:    t.issuer,
		Audience:  s.ClientID,
		IssuedAt:  now,
		JTI:       jti,
		TxN:       txn,
		SubjectID: subID,
		Event:     et,
		Payload:   payload,
	})
	if err != nil {
		t.emitFailed(ctx, et, s.ClientID, s.ID, reasonClaims, err)
		return "", err
	}
	ev := &store.SSFEvent{
		JTI:           jti,
		StreamID:      s.ID,
		Kind:          kind,
		Delivery:      s.Delivery.Method,
		Held:          held,
		Claims:        claims,
		NextAttemptAt: now,
		ExpiresAt:     now.Add(eventTTL),
	}
	if err := t.events.Enqueue(ctx, ev); err != nil {
		t.emitFailed(ctx, et, s.ClientID, s.ID, reasonEnqueue, err)
		return "", fmt.Errorf("ssf: enqueue for stream %q: %w", s.ID, err)
	}
	t.audit.Emit(context.WithoutCancel(ctx), audit.Event{
		Name:     eventEnqueued,
		Level:    audit.LevelInfo,
		Message:  "security event token enqueued",
		ClientID: s.ClientID,
		Extras: map[string]any{
			"stream_id":  s.ID,
			"jti":        jti,
			"event_type": string(et),
			"delivery":   string(s.Delivery.Method),
			"held":       held,
		},
	})
	return jti, nil
}

// emitFailed records an ssf.enqueue_failed event. clientID and streamID
// are empty for failures before any receiver is resolved.
func (t *Transmitter) emitFailed(ctx context.Context, et EventType, clientID, streamID, reason string, cause error) {
	extras := map[string]any{
		"event_type": string(et),
		"reason":     reason,
		"error":      cause.Error(),
	}
	if streamID != "" {
		extras["stream_id"] = streamID
	}
	t.audit.Emit(context.WithoutCancel(ctx), audit.Event{
		Name:     eventEnqueueFailed,
		Level:    audit.LevelError,
		Message:  "security event token not enqueued",
		ClientID: clientID,
		Extras:   extras,
	})
}
