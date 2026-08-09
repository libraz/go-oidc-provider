package audit_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn/audit"
)

// recordingObserver collects every event for later assertions.
type recordingObserver struct {
	events []audit.Event
}

func (r *recordingObserver) Observe(_ context.Context, evt audit.Event) {
	r.events = append(r.events, evt)
}

// panickingObserver models a buggy embedder sink: it records that it
// ran and then panics.
type panickingObserver struct {
	calls int
}

func (p *panickingObserver) Observe(_ context.Context, _ audit.Event) {
	p.calls++
	panic("observer blew up")
}

// TestFanOutDispatchesAllObservers asserts FanOut delivers the event
// to every registered observer in registration order.
func TestFanOutDispatchesAllObservers(t *testing.T) {
	t.Parallel()

	a := &recordingObserver{}
	b := &recordingObserver{}
	evt := audit.Event{Subject: "user-1", Outcome: audit.Success, Factor: "password"}

	audit.FanOut(context.Background(), quietLogger(), []audit.Observer{a, b}, evt)

	if len(a.events) != 1 || a.events[0].Subject != "user-1" {
		t.Errorf("observer a: events = %+v", a.events)
	}
	if len(b.events) != 1 || b.events[0].Subject != "user-1" {
		t.Errorf("observer b: events = %+v", b.events)
	}
}

// TestFanOutSkipsNilEntries asserts a nil entry in the slice is
// silently skipped — the orchestrator's Observers slice may contain
// nil values from a buggy embedder.
func TestFanOutSkipsNilEntries(t *testing.T) {
	t.Parallel()

	a := &recordingObserver{}
	evt := audit.Event{Subject: "user-2"}

	audit.FanOut(context.Background(), quietLogger(), []audit.Observer{nil, a, nil}, evt)

	if len(a.events) != 1 {
		t.Fatalf("events = %+v, want 1", a.events)
	}
}

// TestFanOutIsolatesObserverPanic asserts a panicking observer neither
// escapes to the caller (which would turn a login into a 500) nor
// aborts the remaining fan-out (which would silently stop feeding the
// brute-force counters registered after it).
func TestFanOutIsolatesObserverPanic(t *testing.T) {
	t.Parallel()

	first := &recordingObserver{}
	boom := &panickingObserver{}
	last := &recordingObserver{}
	evt := audit.Event{Subject: "user-3", Outcome: audit.Failure, Factor: "password"}

	audit.FanOut(context.Background(), quietLogger(), []audit.Observer{first, boom, last}, evt)

	if boom.calls != 1 {
		t.Errorf("panicking observer calls = %d, want 1", boom.calls)
	}
	if len(first.events) != 1 {
		t.Errorf("observer before the panic: events = %+v, want 1", first.events)
	}
	if len(last.events) != 1 {
		t.Errorf("observer after the panic: events = %+v, want 1", last.events)
	}
}

// TestFanOutIsolatesConsecutivePanics asserts every observer is
// attempted even when more than one of them panics, so a single broken
// sink cannot mask a second one.
func TestFanOutIsolatesConsecutivePanics(t *testing.T) {
	t.Parallel()

	firstBoom := &panickingObserver{}
	secondBoom := &panickingObserver{}
	survivor := &recordingObserver{}

	audit.FanOut(context.Background(), quietLogger(), []audit.Observer{firstBoom, secondBoom, survivor}, audit.Event{Subject: "user-4"})

	if firstBoom.calls != 1 || secondBoom.calls != 1 {
		t.Errorf("calls = %d / %d, want 1 / 1", firstBoom.calls, secondBoom.calls)
	}
	if len(survivor.events) != 1 {
		t.Errorf("survivor events = %+v, want 1", survivor.events)
	}
}

// quietLogger returns a logger that discards every record. Tests that
// deliberately drive a panicking observer use it so the expected
// error record does not pollute the test output; the tests that assert
// on the record build their own buffer-backed logger instead.
func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestFanOutPanicIsLogged asserts the recovered panic is surfaced on
// the logger the caller supplied rather than swallowed. The OP threads
// its configured logger here, so an embedder that routes OP logs into
// their own pipeline sees a broken observer there.
func TestFanOutPanicIsLogged(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	audit.FanOut(context.Background(), logger, []audit.Observer{&panickingObserver{}}, audit.Event{Factor: "totp"})

	got := buf.String()
	if !strings.Contains(got, "login-attempt observer panicked") {
		t.Fatalf("log output = %q, want the observer-panic record", got)
	}
	if !strings.Contains(got, "observer blew up") {
		t.Errorf("log output = %q, want the recovered panic value", got)
	}
	if !strings.Contains(got, "factor=totp") {
		t.Errorf("log output = %q, want the factor attribute", got)
	}
}

// TestFanOutPanicNilLoggerFallsBackToDefault pins the nil-logger
// contract: a caller that has not wired a logger still gets the report
// instead of silence.
//
//nolint:paralleltest // serial by design — swaps the process-wide default logger.
func TestFanOutPanicNilLoggerFallsBackToDefault(t *testing.T) {
	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	audit.FanOut(context.Background(), nil, []audit.Observer{&panickingObserver{}}, audit.Event{Factor: "totp"})

	if got := buf.String(); !strings.Contains(got, "login-attempt observer panicked") {
		t.Fatalf("log output = %q, want the observer-panic record on the default logger", got)
	}
}
