package ssf

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/netsec"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Receiver-input bounds.
const (
	mgmtMaxDescription = 256      // runes; longer descriptions are truncated
	mgmtMaxAuthzHeader = 4 * 1024 // bytes
)

// HandlerDeps are the dependencies of the management, status,
// verification and poll endpoints.
type HandlerDeps struct {
	// Issuer is the OP issuer: the iss of every stream, and the value a
	// management token's audience must contain. Required.
	Issuer string

	// Bearer accepts the receiver's access token. Its Issuer must equal
	// Issuer.
	Bearer endpointsupport.BearerDeps

	// Streams and Events are the SSF substores. Required.
	Streams store.SSFStreamStore
	Events  store.SSFEventStore

	// Transmitter enqueues the stream-updated and verification control
	// events. Required.
	Transmitter *Transmitter

	// Sealer seals a push stream's authorization_header. Required.
	Sealer *Sealer

	// PollEndpoint is the absolute poll endpoint URL without the stream
	// segment; a poll stream advertises PollEndpoint + "/" + stream_id.
	// Required.
	PollEndpoint string

	// ActiveKey returns the key a polled SET is signed with. It is
	// called per poll response so a rotation takes effect at once.
	// Required.
	ActiveKey func() (SigningKey, error)

	// AllowInsecureForDev admits http and loopback push endpoints
	// (development only).
	AllowInsecureForDev bool

	// AllowPrivateNetwork admits private-network IP literal push
	// endpoints. Cloud metadata addresses stay refused.
	AllowPrivateNetwork bool

	// Audit receives ssf.stream.* and ssf.poll_set_error. Nil discards.
	Audit audit.Emitter

	// Clock stamps stream times. Nil is the system clock.
	Clock timex.Clock
}

// PollPathValue is the [http.Request.PathValue] name the poll handler
// reads the stream_id from; the route is mounted as
// "{poll path}/{stream_id}".
const PollPathValue = "stream_id"

// Handlers serves the SSF management API and the poll endpoint. Safe for
// concurrent use.
type Handlers struct {
	issuer        string
	bearer        endpointsupport.BearerDeps
	streams       store.SSFStreamStore
	events        store.SSFEventStore
	tx            *Transmitter
	sealer        *Sealer
	pollEndpoint  string
	activeKey     func() (SigningKey, error)
	allowInsecure bool
	allowPrivate  bool
	audit         audit.Emitter
	clock         timex.Clock

	// pollInterval and pollWait shape the long poll; tests shorten them.
	pollInterval time.Duration
	pollWait     time.Duration
}

// NewHandlers validates d and builds the endpoint handlers.
func NewHandlers(d HandlerDeps) (*Handlers, error) {
	switch {
	case d.Issuer == "":
		return nil, errors.New("ssf: HandlerDeps.Issuer is empty")
	case d.Bearer.Issuer != d.Issuer:
		return nil, errors.New("ssf: HandlerDeps.Bearer.Issuer must equal Issuer")
	case d.Streams == nil, d.Events == nil:
		return nil, errors.New("ssf: HandlerDeps.Streams and Events are required")
	case d.Transmitter == nil:
		return nil, errors.New("ssf: HandlerDeps.Transmitter is required")
	case d.Sealer == nil:
		return nil, errors.New("ssf: HandlerDeps.Sealer is required")
	case d.PollEndpoint == "":
		return nil, errors.New("ssf: HandlerDeps.PollEndpoint is empty")
	case d.ActiveKey == nil:
		return nil, errors.New("ssf: HandlerDeps.ActiveKey is required")
	}
	emitter := d.Audit
	if emitter == nil {
		emitter = audit.Discard()
	}
	return &Handlers{
		issuer:        d.Issuer,
		bearer:        d.Bearer,
		streams:       d.Streams,
		events:        d.Events,
		tx:            d.Transmitter,
		sealer:        d.Sealer,
		pollEndpoint:  strings.TrimSuffix(d.PollEndpoint, "/"),
		activeKey:     d.ActiveKey,
		allowInsecure: d.AllowInsecureForDev,
		allowPrivate:  d.AllowPrivateNetwork,
		audit:         emitter,
		clock:         timex.OrSystem(d.Clock),
		pollInterval:  pollDefaultInterval,
		pollWait:      pollDefaultWait,
	}, nil
}

// Streams serves the configuration endpoint (SSF 1.0 §8.1.1): POST
// create, GET read, PATCH update, PUT replace, DELETE.
func (h *Handlers) Streams() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			h.createStream(w, r)
		case http.MethodGet, http.MethodHead:
			h.readStream(w, r)
		case http.MethodPatch:
			h.updateStream(w, r, false)
		case http.MethodPut:
			h.updateStream(w, r, true)
		case http.MethodDelete:
			h.deleteStream(w, r)
		default:
			httpx.MethodNotAllowed(w, "GET, HEAD, POST, PATCH, PUT, DELETE")
		}
	})
}

// Status serves the status endpoint (SSF 1.0 §8.1.2): GET read, POST set.
func (h *Handlers) Status() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead:
			h.readStatus(w, r)
		case http.MethodPost:
			h.setStatus(w, r)
		default:
			httpx.MethodNotAllowed(w, "GET, HEAD, POST")
		}
	})
}

// Verify serves the verification endpoint (SSF 1.0 §8.1.4.2).
func (h *Handlers) Verify() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !httpx.EnforceMethod(w, r, http.MethodPost) {
			return
		}
		h.verify(w, r)
	})
}

// streamConfigJSON is the stream configuration returned to the receiver.
// The sealed authorization_header is never returned.
type streamConfigJSON struct {
	StreamID        string       `json:"stream_id"`
	Iss             string       `json:"iss"`
	Aud             string       `json:"aud"`
	EventsSupported []string     `json:"events_supported"`
	EventsRequested []string     `json:"events_requested"`
	EventsDelivered []string     `json:"events_delivered"`
	Delivery        deliveryJSON `json:"delivery"`
	Description     string       `json:"description,omitempty"`
}

type deliveryJSON struct {
	Method      string `json:"method"`
	EndpointURL string `json:"endpoint_url,omitempty"`
}

func (h *Handlers) streamConfig(s *store.SSFStream) streamConfigJSON {
	d := deliveryJSON{Method: DeliveryURNPoll, EndpointURL: h.pollEndpoint + "/" + url.PathEscape(s.ID)}
	if s.Delivery.Method == store.SSFDeliveryPush {
		d = deliveryJSON{Method: DeliveryURNPush, EndpointURL: s.Delivery.EndpointURL}
	}
	return streamConfigJSON{
		StreamID:        s.ID,
		Iss:             h.issuer,
		Aud:             s.ClientID,
		EventsSupported: SupportedEvents(),
		EventsRequested: mgmtNonNil(s.EventsRequested),
		EventsDelivered: mgmtNonNil(s.EventsDelivered),
		Delivery:        d,
		Description:     s.Description,
	}
}

func mgmtNonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

func (h *Handlers) createStream(w http.ResponseWriter, r *http.Request) {
	clientID, ok := h.authorize(w, r, authManage)
	if !ok {
		return
	}
	body, err := mgmtDecodeObject(w, r)
	if err != nil {
		mgmtWriteBodyError(w, err)
		return
	}
	ctx := r.Context()
	switch _, err := h.streams.GetByClient(ctx, clientID); {
	case err == nil:
		mgmtConflict(w)
		return
	case !errors.Is(err, store.ErrNotFound):
		mgmtServerError(w)
		return
	}
	id, err := NewID()
	if err != nil {
		mgmtServerError(w)
		return
	}
	now := h.clock.Now()
	s := &store.SSFStream{ID: id, ClientID: clientID, Status: store.SSFStreamEnabled, CreatedAt: now, UpdatedAt: now}
	if err := h.applyConfig(s, body, true); err != nil {
		mgmtWriteBodyError(w, err)
		return
	}
	if err := h.streams.Create(ctx, s); err != nil {
		if errors.Is(err, store.ErrConflict) {
			mgmtConflict(w)
			return
		}
		mgmtServerError(w)
		return
	}
	// A failed enqueue is audited as ssf.enqueue_failed by the
	// transmitter; the stream exists, so the creation still succeeds.
	_, _ = h.tx.EnqueueControl(ctx, s, EventVerification, ControlFields{})
	h.emitStream(ctx, auditevent.AuditSSFStreamCreated, "shared signals stream created", s, nil)
	_ = httpx.WriteJSON(w, http.StatusCreated, h.streamConfig(s))
}

func (h *Handlers) readStream(w http.ResponseWriter, r *http.Request) {
	clientID, ok := h.authorize(w, r, authRead)
	if !ok {
		return
	}
	ctx := r.Context()
	id := r.URL.Query().Get("stream_id")
	if id == "" {
		s, err := h.streams.GetByClient(ctx, clientID)
		switch {
		case errors.Is(err, store.ErrNotFound):
			_ = httpx.WriteJSON(w, http.StatusOK, []streamConfigJSON{})
		case err != nil:
			mgmtServerError(w)
		default:
			_ = httpx.WriteJSON(w, http.StatusOK, []streamConfigJSON{h.streamConfig(s)})
		}
		return
	}
	s, ok := h.ownedStream(ctx, w, clientID, id)
	if !ok {
		return
	}
	_ = httpx.WriteJSON(w, http.StatusOK, h.streamConfig(s))
}

// updateStream serves PATCH (replace false) and PUT (replace true).
func (h *Handlers) updateStream(w http.ResponseWriter, r *http.Request, replace bool) {
	clientID, ok := h.authorize(w, r, authManage)
	if !ok {
		return
	}
	body, err := mgmtDecodeObject(w, r)
	if err != nil {
		mgmtWriteBodyError(w, err)
		return
	}
	id, err := mgmtStreamID(body)
	if err != nil {
		mgmtWriteBodyError(w, err)
		return
	}
	ctx := r.Context()
	s, ok := h.ownedStream(ctx, w, clientID, id)
	if !ok {
		return
	}
	if err := h.checkImmutable(s, body); err != nil {
		mgmtWriteBodyError(w, err)
		return
	}
	prevMethod := s.Delivery.Method
	if err := h.applyConfig(s, body, replace); err != nil {
		mgmtWriteBodyError(w, err)
		return
	}
	s.UpdatedAt = h.clock.Now()
	if err := h.streams.Update(ctx, s); err != nil {
		h.writeStoreError(w, err)
		return
	}
	if s.Delivery.Method != prevMethod {
		if err := h.events.Retag(ctx, s.ID, s.Delivery.Method, s.Status == store.SSFStreamPaused); err != nil {
			mgmtServerError(w)
			return
		}
	}
	h.emitStream(ctx, auditevent.AuditSSFStreamUpdated, "shared signals stream updated", s, nil)
	_ = httpx.WriteJSON(w, http.StatusOK, h.streamConfig(s))
}

func (h *Handlers) deleteStream(w http.ResponseWriter, r *http.Request) {
	clientID, ok := h.authorize(w, r, authManage)
	if !ok {
		return
	}
	id := r.URL.Query().Get("stream_id")
	if id == "" {
		mgmtWriteBodyError(w, mgmtBadRequest("stream_id is required"))
		return
	}
	ctx := r.Context()
	s, ok := h.ownedStream(ctx, w, clientID, id)
	if !ok {
		return
	}
	if err := h.streams.Delete(ctx, s.ID); err != nil {
		h.writeStoreError(w, err)
		return
	}
	h.emitStream(ctx, auditevent.AuditSSFStreamDeleted, "shared signals stream deleted", s, nil)
	httpx.StampNoStore(w)
	w.WriteHeader(http.StatusNoContent)
}

// statusJSON is the stream status object (SSF 1.0 §8.1.2).
type statusJSON struct {
	StreamID string `json:"stream_id"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
}

func (h *Handlers) readStatus(w http.ResponseWriter, r *http.Request) {
	clientID, ok := h.authorize(w, r, authRead)
	if !ok {
		return
	}
	id := r.URL.Query().Get("stream_id")
	if id == "" {
		mgmtWriteBodyError(w, mgmtBadRequest("stream_id is required"))
		return
	}
	s, ok := h.ownedStream(r.Context(), w, clientID, id)
	if !ok {
		return
	}
	_ = httpx.WriteJSON(w, http.StatusOK, statusJSON{StreamID: s.ID, Status: string(s.Status), Reason: s.StatusReason})
}

// setStatus enqueues stream-updated before writing the new status, then
// moves the queued ordinary events: paused holds them, enabled releases
// them, disabled drops them. Control events survive every transition.
func (h *Handlers) setStatus(w http.ResponseWriter, r *http.Request) {
	clientID, ok := h.authorize(w, r, authManage)
	if !ok {
		return
	}
	body, err := mgmtDecodeObject(w, r)
	if err != nil {
		mgmtWriteBodyError(w, err)
		return
	}
	id, err := mgmtStreamID(body)
	if err != nil {
		mgmtWriteBodyError(w, err)
		return
	}
	status, err := mgmtStatus(body)
	if err != nil {
		mgmtWriteBodyError(w, err)
		return
	}
	reason, _, err := mgmtString(body, "reason")
	if err != nil {
		mgmtWriteBodyError(w, err)
		return
	}
	ctx := r.Context()
	s, ok := h.ownedStream(ctx, w, clientID, id)
	if !ok {
		return
	}
	changed := s.Status != status
	if changed {
		if _, err := h.tx.EnqueueControl(ctx, s, EventStreamUpdated, ControlFields{Status: status, Reason: reason}); err != nil {
			mgmtServerError(w)
			return
		}
	}
	s.Status = status
	s.StatusReason = reason
	s.UpdatedAt = h.clock.Now()
	if err := h.streams.Update(ctx, s); err != nil {
		h.writeStoreError(w, err)
		return
	}
	if changed {
		if err := h.moveQueued(ctx, s); err != nil {
			mgmtServerError(w)
			return
		}
	}
	h.emitStream(ctx, auditevent.AuditSSFStreamUpdated, "shared signals stream status set", s,
		map[string]any{"status": string(status)})
	_ = httpx.WriteJSON(w, http.StatusOK, statusJSON{StreamID: s.ID, Status: string(s.Status), Reason: s.StatusReason})
}

// moveQueued applies s's new status to its queued ordinary events. It
// runs after the status is stored, so an event published concurrently
// already sees the new status.
func (h *Handlers) moveQueued(ctx context.Context, s *store.SSFStream) error {
	switch s.Status {
	case store.SSFStreamPaused:
		return h.events.Retag(ctx, s.ID, s.Delivery.Method, true)
	case store.SSFStreamEnabled:
		return h.events.Retag(ctx, s.ID, s.Delivery.Method, false)
	case store.SSFStreamDisabled:
		return h.events.Purge(ctx, s.ID, false)
	}
	return nil
}

func (h *Handlers) verify(w http.ResponseWriter, r *http.Request) {
	clientID, ok := h.authorize(w, r, authManage)
	if !ok {
		return
	}
	body, err := mgmtDecodeObject(w, r)
	if err != nil {
		mgmtWriteBodyError(w, err)
		return
	}
	id, err := mgmtStreamID(body)
	if err != nil {
		mgmtWriteBodyError(w, err)
		return
	}
	state, _, err := mgmtString(body, "state")
	if err != nil {
		mgmtWriteBodyError(w, err)
		return
	}
	ctx := r.Context()
	s, ok := h.ownedStream(ctx, w, clientID, id)
	if !ok {
		return
	}
	// The store replaces the stream's pending verification.
	if _, err := h.tx.EnqueueControl(ctx, s, EventVerification, ControlFields{State: state}); err != nil {
		mgmtServerError(w)
		return
	}
	httpx.StampNoStore(w)
	w.WriteHeader(http.StatusNoContent)
}

// ownedStream loads stream id and checks that clientID owns it. Another
// receiver's stream is reported as missing so its existence never leaks.
func (h *Handlers) ownedStream(ctx context.Context, w http.ResponseWriter, clientID, id string) (*store.SSFStream, bool) {
	s, err := h.streams.Get(ctx, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		mgmtNotFound(w)
		return nil, false
	case err != nil:
		mgmtServerError(w)
		return nil, false
	case s.ClientID != clientID:
		mgmtNotFound(w)
		return nil, false
	}
	return s, true
}

func (h *Handlers) writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, store.ErrNotFound) {
		mgmtNotFound(w)
		return
	}
	mgmtServerError(w)
}

func mgmtConflict(w http.ResponseWriter) {
	_ = httpx.WriteError(w, http.StatusConflict, "conflict", "the receiver already has a stream")
}

func (h *Handlers) emitStream(ctx context.Context, name auditevent.Name, msg string, s *store.SSFStream, extra map[string]any) {
	extras := map[string]any{
		"stream_id": s.ID,
		"delivery":  string(s.Delivery.Method),
	}
	for k, v := range extra {
		extras[k] = v
	}
	h.audit.Emit(context.WithoutCancel(ctx), audit.Event{
		Name:     string(name),
		Level:    audit.LevelInfo,
		Message:  msg,
		ActorID:  s.ClientID,
		ClientID: s.ClientID,
		Extras:   extras,
	})
}

// mgmtObject is a decoded request body: member name to raw value, with
// JSON null members removed so null reads as absent.
type mgmtObject map[string]json.RawMessage

// mgmtDecodeObject reads a JSON object body. An empty body is {}.
// Malformed JSON and trailing data are 400; unknown members are kept and
// ignored by the callers.
func mgmtDecodeObject(w http.ResponseWriter, r *http.Request) (mgmtObject, error) {
	b, err := mgmtReadBody(w, r)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		return mgmtObject{}, nil
	}
	var obj mgmtObject
	if err := json.Unmarshal(b, &obj); err != nil {
		return nil, mgmtBadRequest("malformed JSON body")
	}
	if obj == nil {
		return nil, mgmtBadRequest("request body must be a JSON object")
	}
	for k, v := range obj {
		if string(v) == "null" {
			delete(obj, k)
		}
	}
	return obj, nil
}

// mgmtString decodes member name as a string, reporting whether it was
// present.
func mgmtString(obj mgmtObject, name string) (string, bool, error) {
	raw, ok := obj[name]
	if !ok {
		return "", false, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", true, mgmtBadRequest(name + " must be a string")
	}
	return s, true, nil
}

// mgmtStrings decodes member name as an array of strings.
func mgmtStrings(obj mgmtObject, name string) ([]string, bool, error) {
	raw, ok := obj[name]
	if !ok {
		return nil, false, nil
	}
	var v []string
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, true, mgmtBadRequest(name + " must be an array of strings")
	}
	return v, true, nil
}

func mgmtStreamID(obj mgmtObject) (string, error) {
	id, _, err := mgmtString(obj, "stream_id")
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", mgmtBadRequest("stream_id is required")
	}
	return id, nil
}

func mgmtStatus(obj mgmtObject) (store.SSFStreamStatus, error) {
	v, _, err := mgmtString(obj, "status")
	if err != nil {
		return "", err
	}
	switch s := store.SSFStreamStatus(v); s {
	case store.SSFStreamEnabled, store.SSFStreamPaused, store.SSFStreamDisabled:
		return s, nil
	}
	return "", mgmtBadRequest("status must be enabled, paused or disabled")
}

// checkImmutable refuses an update that tries to change a member the
// transmitter owns: stream_id is matched by lookup; iss, aud and
// events_delivered must equal the stored values when sent.
func (h *Handlers) checkImmutable(s *store.SSFStream, obj mgmtObject) error {
	iss, ok, err := mgmtString(obj, "iss")
	if err != nil {
		return err
	}
	if ok && iss != h.issuer {
		return mgmtBadRequest("iss cannot be changed")
	}
	if raw, ok := obj["aud"]; ok {
		var one string
		var many []string
		switch {
		case json.Unmarshal(raw, &one) == nil:
			many = []string{one}
		case json.Unmarshal(raw, &many) == nil:
		default:
			return mgmtBadRequest("aud must be a string or an array of strings")
		}
		if len(many) != 1 || many[0] != s.ClientID {
			return mgmtBadRequest("aud cannot be changed")
		}
	}
	delivered, sent, err := mgmtStrings(obj, "events_delivered")
	if err != nil {
		return err
	}
	if sent && !mgmtSameSet(delivered, s.EventsDelivered) {
		return mgmtBadRequest("events_delivered cannot be set by the receiver")
	}
	return nil
}

func mgmtSameSet(a, b []string) bool {
	for _, v := range a {
		if !slices.Contains(b, v) {
			return false
		}
	}
	for _, v := range b {
		if !slices.Contains(a, v) {
			return false
		}
	}
	return true
}

// applyConfig applies the receiver-settable members (delivery,
// events_requested, description) to s. With replace, an omitted member
// is reset (PUT, and creation); otherwise it is kept (PATCH).
func (h *Handlers) applyConfig(s *store.SSFStream, obj mgmtObject, replace bool) error {
	requested, ok, err := mgmtStrings(obj, "events_requested")
	if err != nil {
		return err
	}
	if ok || replace {
		s.EventsRequested = mgmtNonNil(requested)
		s.EventsDelivered = mgmtDeliverable(requested)
	}
	desc, ok, err := mgmtString(obj, "description")
	if err != nil {
		return err
	}
	if ok || replace {
		s.Description = mgmtTruncate(desc, mgmtMaxDescription)
	}
	return h.applyDelivery(s, obj, replace)
}

// mgmtDeliverable is supported ∩ requested, in supported order.
func mgmtDeliverable(requested []string) []string {
	out := []string{}
	for _, e := range SupportedEvents() {
		if slices.Contains(requested, e) {
			out = append(out, e)
		}
	}
	return out
}

func mgmtTruncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// mgmtDeliveryInput is the decoded delivery member.
type mgmtDeliveryInput struct {
	method                 store.SSFDeliveryMethod
	endpoint, header       string
	hasEndpoint, hasHeader bool
}

func mgmtDecodeDelivery(raw json.RawMessage) (mgmtDeliveryInput, error) {
	var obj mgmtObject
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return mgmtDeliveryInput{}, mgmtBadRequest("delivery must be an object")
	}
	for k, v := range obj {
		if string(v) == "null" {
			delete(obj, k)
		}
	}
	var in mgmtDeliveryInput
	method, ok, err := mgmtString(obj, "method")
	if err != nil {
		return in, err
	}
	if ok {
		switch method {
		case DeliveryURNPush:
			in.method = store.SSFDeliveryPush
		case DeliveryURNPoll:
			in.method = store.SSFDeliveryPoll
		default:
			return in, mgmtBadRequest("delivery.method is not supported")
		}
	}
	if in.endpoint, in.hasEndpoint, err = mgmtString(obj, "endpoint_url"); err != nil {
		return in, err
	}
	if in.header, in.hasHeader, err = mgmtString(obj, "authorization_header"); err != nil {
		return in, err
	}
	return in, nil
}

// applyDelivery sets s.Delivery. A PATCH that names only some delivery
// members keeps the others, including the sealed authorization header;
// a replace without delivery makes a poll stream, and a replace without
// authorization_header drops the sealed value.
func (h *Handlers) applyDelivery(s *store.SSFStream, obj mgmtObject, replace bool) error {
	raw, present := obj["delivery"]
	if !present {
		if replace {
			s.Delivery = store.SSFDelivery{Method: store.SSFDeliveryPoll}
		}
		return nil
	}
	in, err := mgmtDecodeDelivery(raw)
	if err != nil {
		return err
	}
	cur := s.Delivery
	if replace {
		if in.method == "" {
			return mgmtBadRequest("delivery.method is required")
		}
		cur = store.SSFDelivery{}
	}
	method := in.method
	if method == "" {
		method = cur.Method
	}
	if method == store.SSFDeliveryPoll {
		// The transmitter supplies the poll endpoint; receiver values are ignored.
		s.Delivery = store.SSFDelivery{Method: store.SSFDeliveryPoll}
		return nil
	}
	next, err := h.pushDelivery(s.ID, cur, in)
	if err != nil {
		return err
	}
	s.Delivery = next
	return nil
}

// pushDelivery merges in over cur (kept only when cur is push) into a
// validated push delivery, sealing a new authorization header.
func (h *Handlers) pushDelivery(streamID string, cur store.SSFDelivery, in mgmtDeliveryInput) (store.SSFDelivery, error) {
	next := store.SSFDelivery{Method: store.SSFDeliveryPush}
	if cur.Method == store.SSFDeliveryPush {
		next.EndpointURL = cur.EndpointURL
		next.SealedAuthorizationHeader = cur.SealedAuthorizationHeader
	}
	if in.hasEndpoint {
		next.EndpointURL = in.endpoint
	}
	if err := h.checkPushEndpoint(next.EndpointURL); err != nil {
		return next, err
	}
	if !in.hasHeader {
		return next, nil
	}
	if err := mgmtCheckHeader(in.header); err != nil {
		return next, err
	}
	next.SealedAuthorizationHeader = nil
	if in.header != "" {
		next.SealedAuthorizationHeader = h.sealer.Seal(streamID, in.header)
	}
	return next, nil
}

func mgmtCheckHeader(v string) error {
	if len(v) > mgmtMaxAuthzHeader {
		return mgmtBadRequest("delivery.authorization_header is too long")
	}
	for i := range len(v) {
		if c := v[i]; c < 0x20 || c == 0x7F {
			return mgmtBadRequest("delivery.authorization_header contains a control character")
		}
	}
	return nil
}

// checkPushEndpoint is the creation-time syntax and IP-literal check of a
// push endpoint; the dial-time SSRF gate runs again at every delivery.
func (h *Handlers) checkPushEndpoint(raw string) error {
	if raw == "" {
		return mgmtBadRequest("delivery.endpoint_url is required for push")
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Opaque != "" {
		return mgmtBadRequest("delivery.endpoint_url must be an absolute URL")
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && h.allowInsecure:
	default:
		return mgmtBadRequest("delivery.endpoint_url must use https")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return mgmtBadRequest("delivery.endpoint_url must not carry a fragment")
	}
	if u.User != nil {
		return mgmtBadRequest("delivery.endpoint_url must not carry userinfo")
	}
	if !h.pushHostAllowed(u.Hostname()) {
		return mgmtBadRequest("delivery.endpoint_url must not be a local address")
	}
	return nil
}

// pushHostAllowed applies the opt-in flags to a local hostname or an IP
// literal host. Cloud metadata addresses are refused under every flag.
func (h *Handlers) pushHostAllowed(host string) bool {
	if netsec.IsLocalHostname(host) {
		return h.allowInsecure || h.allowPrivate
	}
	ip := net.ParseIP(host)
	switch {
	case ip == nil:
		return true
	case netsec.IsCloudMetadataIP(ip):
		return false
	case h.allowPrivate:
		return true
	case ip.IsLoopback() && h.allowInsecure:
		return true
	}
	return !netsec.IsPrivateIP(ip)
}
