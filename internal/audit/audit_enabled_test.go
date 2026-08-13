package audit_test

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/audit"
)

// Handler code emits audit events unconditionally — there is no
// call-site guard, by design, because a guard at every site is a guard
// somebody forgets. That makes the emitter the only place a deployment
// that is not listening can stop paying for the event, and flattening
// one is not free: every canonical field is appended and every Extras
// value goes through the redactor. The silent default (no WithLogger,
// no WithAuditLogger) is exactly that shape, so the skip is checked
// rather than assumed.

// countingHandler records what the emitter asked of it. Enabled answers
// from the flag so one type plays both the filtered-out sink and the
// live one.
type countingHandler struct {
	enabled  bool
	enabledN atomic.Int64
	handleN  atomic.Int64
}

func (h *countingHandler) Enabled(context.Context, slog.Level) bool {
	h.enabledN.Add(1)
	return h.enabled
}

func (h *countingHandler) Handle(context.Context, slog.Record) error {
	h.handleN.Add(1)
	return nil
}

func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *countingHandler) WithGroup(string) slog.Handler { return h }

// populatedEvent carries every canonical field plus an Extras map, so
// the attr-building work the skip is meant to avoid is substantial
// enough to be visible.
func populatedEvent() audit.Event {
	return audit.Event{
		Name:      "token.issued",
		Message:   "token issued",
		ActorID:   "sub-1",
		ClientID:  "rp-1",
		SessionID: "sess-1",
		RequestID: "req-1",
		IP:        "203.0.113.7",
		UserAgent: "curl/8",
		Tag:       "tag-1",
		Extras: map[string]any{
			"grant_id":      "g-1",
			"refresh_token": "should-be-masked",
			"rotation":      3,
		},
	}
}

// TestSlogEmitterSkipsAttrBuildingWhenHandlerIsDisabled pins both halves
// of the short-circuit: that the emitter asks the handler at all, and
// that a "no" ends the call before the event is flattened.
//
// The second half is asserted through allocation count because
// flattening leaves no other trace: the attrs are handed straight to a
// handler that is not going to be called, so nothing downstream can be
// asked whether they were built. Zero is the assertion rather than
// "fewer than the enabled path" — slog's own LogAttrs consults Enabled
// and drops the record too, so an emitter with no guard of its own
// still allocates less on the disabled path than on the live one while
// having built every attr. Flattening a populated event cannot happen
// allocation-free (the attr slice alone is one), so a non-zero count
// here is the work having been done and thrown away.
//
//nolint:paralleltest // testing.AllocsPerRun pins GOMAXPROCS and panics when called from a parallel test.
func TestSlogEmitterSkipsAttrBuildingWhenHandlerIsDisabled(t *testing.T) {
	ctx := context.Background()
	ev := populatedEvent()

	off := &countingHandler{enabled: false}
	offEmitter := audit.Slog(slog.New(off))

	offEmitter.Emit(ctx, ev)
	if got := off.enabledN.Load(); got != 1 {
		t.Errorf("Enabled consulted %d times, want exactly 1; the emitter is not asking the handler "+
			"whether the record is wanted before building it", got)
	}
	if got := off.handleN.Load(); got != 0 {
		t.Errorf("Handle called %d times on a disabled handler, want 0", got)
	}

	on := &countingHandler{enabled: true}
	onEmitter := audit.Slog(slog.New(on))

	offAllocs := testing.AllocsPerRun(100, func() { offEmitter.Emit(ctx, ev) })
	onAllocs := testing.AllocsPerRun(100, func() { onEmitter.Emit(ctx, ev) })

	if on.handleN.Load() == 0 {
		t.Fatal("the enabled handler was never called; the baseline event never reached a sink")
	}
	if onAllocs == 0 {
		t.Fatal("an enabled emit of a fully populated event allocated nothing; the baseline is not " +
			"exercising the flattening the disabled path is supposed to skip")
	}
	if offAllocs != 0 {
		t.Errorf("a disabled emit allocates %v (an enabled one allocates %v); flattening a populated "+
			"event cannot be allocation-free, so the disabled path is still building the attrs and "+
			"discarding them", offAllocs, onAllocs)
	}
}
