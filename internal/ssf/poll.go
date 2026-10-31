package ssf

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Poll bounds (RFC 8936 §2.4).
const (
	pollDefaultMax = 32
	pollCapMax     = 256
)

// Long-poll shape (RFC 8936 §2.5): with nothing pending and
// returnImmediately false, Pending is re-read every interval until the
// wait ends.
const (
	pollDefaultInterval = time.Second
	pollDefaultWait     = 10 * time.Second
)

// pollRequest is the decoded RFC 8936 §2.4 request.
type pollRequest struct {
	maxEvents   int
	immediately bool
	ack         []string
	setErrs     map[string]pollSetErr
}

type pollSetErr struct {
	Err         string `json:"err"`
	Description string `json:"description"`
}

type pollResponse struct {
	Sets          map[string]string `json:"sets"`
	MoreAvailable bool              `json:"moreAvailable,omitempty"`
}

// Poll serves POST {poll endpoint}/{stream_id} (RFC 8936). It accepts
// ssf.read or ssf.manage.
func (h *Handlers) Poll() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !httpx.EnforceMethod(w, r, http.MethodPost) {
			return
		}
		h.poll(w, r)
	})
}

func (h *Handlers) poll(w http.ResponseWriter, r *http.Request) {
	clientID, ok := h.authorize(w, r, authRead)
	if !ok {
		return
	}
	obj, err := mgmtDecodeObject(w, r)
	if err != nil {
		mgmtWriteBodyError(w, err)
		return
	}
	req, err := pollDecode(obj)
	if err != nil {
		mgmtWriteBodyError(w, err)
		return
	}
	ctx := r.Context()
	s, ok := h.ownedStream(ctx, w, clientID, r.PathValue(PollPathValue))
	if !ok {
		return
	}
	if s.Delivery.Method != store.SSFDeliveryPoll {
		mgmtWriteBodyError(w, mgmtBadRequest("the stream does not use poll delivery"))
		return
	}
	if err := h.pollAcknowledge(ctx, s, req); err != nil {
		mgmtServerError(w)
		return
	}
	resp := pollResponse{Sets: map[string]string{}}
	if req.maxEvents > 0 {
		evs, more, err := h.pollPending(ctx, s.ID, req)
		if err != nil {
			mgmtServerError(w)
			return
		}
		if err := h.pollSign(evs, resp.Sets); err != nil {
			mgmtServerError(w)
			return
		}
		resp.MoreAvailable = more
	}
	_ = httpx.WriteJSON(w, http.StatusOK, resp)
}

// pollSign signs evs with the key active now into sets, keyed by jti.
func (h *Handlers) pollSign(evs []*store.SSFEvent, sets map[string]string) error {
	if len(evs) == 0 {
		return nil
	}
	key, err := h.activeKey()
	if err != nil {
		return err
	}
	for _, ev := range evs {
		set, err := Sign(ev.Claims, key)
		if err != nil {
			return err
		}
		sets[ev.JTI] = set
	}
	return nil
}

// pollAcknowledge drops the acknowledged SETs and the ones the receiver
// reported errors for, auditing each error.
func (h *Handlers) pollAcknowledge(ctx context.Context, s *store.SSFStream, req pollRequest) error {
	if len(req.ack) > 0 {
		if err := h.events.Ack(ctx, s.ID, req.ack); err != nil {
			return err
		}
	}
	if len(req.setErrs) == 0 {
		return nil
	}
	jtis := make([]string, 0, len(req.setErrs))
	for jti := range req.setErrs {
		jtis = append(jtis, jti)
	}
	if err := h.events.Ack(ctx, s.ID, jtis); err != nil {
		return err
	}
	for jti, e := range req.setErrs {
		h.audit.Emit(context.WithoutCancel(ctx), audit.Event{
			Name:     string(auditevent.AuditSSFPollSETError),
			Level:    audit.LevelWarn,
			Message:  "receiver reported a security event token error",
			ActorID:  s.ClientID,
			ClientID: s.ClientID,
			Extras: map[string]any{
				"stream_id":   s.ID,
				"jti":         jti,
				"err":         e.Err,
				"description": e.Description,
			},
		})
	}
	return nil
}

// pollPending returns the stream's pending SETs, waiting for one to
// arrive when the request allows it.
func (h *Handlers) pollPending(ctx context.Context, streamID string, req pollRequest) ([]*store.SSFEvent, bool, error) {
	evs, more, err := h.events.Pending(ctx, streamID, req.maxEvents)
	if err != nil || len(evs) > 0 || req.immediately {
		return evs, more, err
	}
	deadline := time.NewTimer(h.pollWait)
	defer deadline.Stop()
	tick := time.NewTicker(h.pollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, false, nil
		case <-deadline.C:
			return nil, false, nil
		case <-tick.C:
			evs, more, err = h.events.Pending(ctx, streamID, req.maxEvents)
			if err != nil || len(evs) > 0 {
				return evs, more, err
			}
		}
	}
}

// pollDecode validates the request members. maxEvents must be a
// non-negative integer and is capped; ack must be strings; every setErrs
// value must be an object.
func pollDecode(obj mgmtObject) (pollRequest, error) {
	req := pollRequest{maxEvents: pollDefaultMax}
	if raw, ok := obj["maxEvents"]; ok {
		n, err := pollMaxEvents(raw)
		if err != nil {
			return req, err
		}
		req.maxEvents = n
	}
	if raw, ok := obj["returnImmediately"]; ok {
		if err := json.Unmarshal(raw, &req.immediately); err != nil {
			return req, mgmtBadRequest("returnImmediately must be a boolean")
		}
	}
	ack, _, err := mgmtStrings(obj, "ack")
	if err != nil {
		return req, err
	}
	req.ack = ack
	if raw, ok := obj["setErrs"]; ok {
		if req.setErrs, err = pollSetErrs(raw); err != nil {
			return req, err
		}
	}
	return req, nil
}

func pollSetErrs(raw json.RawMessage) (map[string]pollSetErr, error) {
	var errs map[string]json.RawMessage
	if err := json.Unmarshal(raw, &errs); err != nil || errs == nil {
		return nil, mgmtBadRequest("setErrs must be an object")
	}
	out := make(map[string]pollSetErr, len(errs))
	for jti, v := range errs {
		var e pollSetErr
		if len(v) == 0 || v[0] != '{' || json.Unmarshal(v, &e) != nil {
			return nil, mgmtBadRequest("every setErrs value must be an object")
		}
		out[jti] = e
	}
	return out, nil
}

func pollMaxEvents(raw json.RawMessage) (int, error) {
	bad := mgmtBadRequest("maxEvents must be a non-negative integer")
	var num json.Number
	if len(raw) == 0 || raw[0] == '"' || json.Unmarshal(raw, &num) != nil {
		return 0, bad
	}
	n, err := strconv.ParseInt(num.String(), 10, 64)
	if errors.Is(err, strconv.ErrRange) && n > 0 {
		return pollCapMax, nil
	}
	if err != nil || n < 0 {
		return 0, bad
	}
	return int(min(n, pollCapMax)), nil
}
