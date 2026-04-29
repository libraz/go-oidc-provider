package op_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
)

func TestNewInMemoryDPoPNonceSource_RejectsNonPositiveRotation(t *testing.T) {
	t.Parallel()

	for _, d := range []time.Duration{0, -time.Second} {
		if _, err := op.NewInMemoryDPoPNonceSource(context.Background(), d); err == nil {
			t.Errorf("rotate=%v: expected error, got nil", d)
		}
	}
}

func TestNewInMemoryDPoPNonceSource_IssuesNonEmptyValue(t *testing.T) {
	t.Parallel()

	src, err := op.NewInMemoryDPoPNonceSource(context.Background(), time.Hour)
	if err != nil {
		t.Fatalf("NewInMemoryDPoPNonceSource: %v", err)
	}
	if got := src.IssueNonce(); got == "" {
		t.Errorf("IssueNonce returned empty string before rotation")
	}
}

func TestNewInMemoryDPoPNonceSource_ValidatesCurrent(t *testing.T) {
	t.Parallel()

	src, err := op.NewInMemoryDPoPNonceSource(context.Background(), time.Hour)
	if err != nil {
		t.Fatalf("NewInMemoryDPoPNonceSource: %v", err)
	}
	current := src.IssueNonce()
	if !src.Validate(current) {
		t.Errorf("Validate(current=%q) = false, want true", current)
	}
	if src.Validate("") {
		t.Errorf("Validate(empty) = true, want false")
	}
	if src.Validate("never-issued") {
		t.Errorf("Validate(never-issued) = true, want false")
	}
}

func TestNewInMemoryDPoPNonceSource_AcceptsPreviousAcrossRotation(t *testing.T) {
	t.Parallel()

	src, err := op.NewInMemoryDPoPNonceSource(context.Background(), 20*time.Millisecond)
	if err != nil {
		t.Fatalf("NewInMemoryDPoPNonceSource: %v", err)
	}
	first := src.IssueNonce()

	// Wait for at least one rotation to occur.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if next := src.IssueNonce(); next != first {
			// Rotation happened. The previous value MUST still
			// validate so an in-flight client retry that straddles
			// the boundary does not get rejected.
			if !src.Validate(first) {
				t.Errorf("Validate(previous=%q) = false after rotation, want true", first)
			}
			if !src.Validate(next) {
				t.Errorf("Validate(current=%q) = false, want true", next)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("nonce did not rotate within deadline (first=%q)", first)
}

func TestNewInMemoryDPoPNonceSource_StopsRotatingOnCancel(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	src, err := op.NewInMemoryDPoPNonceSource(ctx, 10*time.Millisecond)
	if err != nil {
		t.Fatalf("NewInMemoryDPoPNonceSource: %v", err)
	}
	cancel()

	// Give the rotation goroutine time to observe the cancellation.
	time.Sleep(50 * time.Millisecond)
	frozen := src.IssueNonce()
	time.Sleep(40 * time.Millisecond)
	if got := src.IssueNonce(); got != frozen {
		t.Errorf("IssueNonce kept rotating after ctx.Cancel: frozen=%q later=%q", frozen, got)
	}
	// Validation MUST keep working after cancellation; embedders rely
	// on in-flight RP retries succeeding even when the OP is shutting
	// down.
	if !src.Validate(frozen) {
		t.Errorf("Validate(%q) = false after cancel; helper must keep accepting the last issued nonce", frozen)
	}
}

func TestNewInMemoryDPoPNonceSource_ProducesUniqueValues(t *testing.T) {
	t.Parallel()

	seen := make(map[string]struct{}, 64)
	for i := range 64 {
		src, err := op.NewInMemoryDPoPNonceSource(context.Background(), time.Hour)
		if err != nil {
			t.Fatalf("NewInMemoryDPoPNonceSource: %v", err)
		}
		v := src.IssueNonce()
		if v == "" || strings.ContainsAny(v, "+/=") {
			t.Errorf("nonce=%q is not non-empty base64url", v)
		}
		if _, dup := seen[v]; dup {
			t.Errorf("nonce %q collided after %d samples", v, i)
		}
		seen[v] = struct{}{}
	}
}

// errFlakyReader is the sentinel the test reader returns on every
// post-seed read so the assertion can identify it via errors.Is if
// future test logic needs that.
var errFlakyReader = errors.New("flaky entropy")

// flakyReader returns errFlakyReader on every Read after the first
// successful call so the constructor's seed read still succeeds while
// the rotation goroutine's subsequent reads always fail. The first
// Read fills the buffer with a deterministic byte so the seeded
// nonce remains valid base64url.
type flakyReader struct {
	calls atomic.Int32
}

func (r *flakyReader) Read(p []byte) (int, error) {
	n := r.calls.Add(1)
	if n == 1 {
		// Seed the constructor with a deterministic but valid value
		// so NewInMemoryDPoPNonceSource succeeds and the rotation
		// goroutine can begin ticking. We do not care about the
		// content beyond "non-zero".
		for i := range p {
			p[i] = 0x42
		}
		return len(p), nil
	}
	return 0, errFlakyReader
}

// TestNewInMemoryDPoPNonceSource_LogsAndCountsRotationFailures pins the
// F-1 contract: when the configured entropy source fails on a rotation
// tick, the helper increments [InMemoryDPoPNonceSource.RotationFailures]
// and emits a WARN line through the logger threaded in via
// [WithInMemoryDPoPNonceLogger]. The previous nonce stays serviceable
// so the wire posture documents in the godoc holds.
func TestNewInMemoryDPoPNonceSource_LogsAndCountsRotationFailures(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})
	logger := slog.New(handler)
	reader := &flakyReader{}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	src, err := op.NewInMemoryDPoPNonceSource(
		ctx,
		10*time.Millisecond,
		op.WithInMemoryDPoPNonceLogger(logger),
		op.WithInMemoryDPoPNonceRandForTest(reader),
	)
	if err != nil {
		t.Fatalf("NewInMemoryDPoPNonceSource: %v", err)
	}

	// Wait until at least one rotation failure has been observed.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if src.RotationFailures() >= 1 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if got := src.RotationFailures(); got < 1 {
		t.Fatalf("RotationFailures = %d, want >= 1", got)
	}
	cancel()

	// The WARN line MUST mention the rotation_failures counter so an
	// operator scraping logs sees the running count alongside each
	// emission.
	out := buf.String()
	if !strings.Contains(out, "rotation_failures") {
		t.Errorf("log output missing rotation_failures attribute: %q", out)
	}
	// Confirm the line is a structured WARN record, not a casual
	// fmt.Println — JSON envelopes are the contract for embedders
	// piping the OP's logger into ELK / Loki / BigQuery.
	dec := json.NewDecoder(strings.NewReader(out))
	for dec.More() {
		var rec map[string]any
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("decode log line: %v", err)
		}
		if rec["level"] != "WARN" {
			t.Errorf("log level=%v, want WARN", rec["level"])
		}
	}
	// Validation must still accept the seeded nonce; the helper's
	// degraded mode keeps the previous value live.
	if !src.Validate(src.IssueNonce()) {
		t.Errorf("Validate(current) = false during rotation outage; helper must keep the previous value live")
	}
}

// TestInMemoryDPoPNonceSource_ValidateUsesConstantTimeCompare pins the
// F-2 contract: a bad input MUST NOT short-circuit through a fast
// `nonce == s.current` mismatch. The test cannot directly observe the
// ConstantTimeCompare call (that would require unsafe reflection) but
// it pins the behavioural symptom — every accepted/rejected branch
// returns the expected boolean even when the test input length differs
// from the stored value, so the helper's length-padding scratch buffer
// path is exercised. A regression that re-introduced the
// short-circuit `==` would still pass these checks; the timing-side
// guarantee is delivered by the godoc + microbench in v1.x.
func TestInMemoryDPoPNonceSource_ValidateUsesConstantTimeCompare(t *testing.T) {
	t.Parallel()

	src, err := op.NewInMemoryDPoPNonceSource(context.Background(), time.Hour)
	if err != nil {
		t.Fatalf("NewInMemoryDPoPNonceSource: %v", err)
	}
	current := src.IssueNonce()

	// Same length as current but every byte different — the compare
	// path runs the full length without leaking the position of the
	// first mismatch.
	mismatch := strings.Repeat("a", len(current))
	if mismatch == current {
		// Astronomically unlikely; pad to break the equality.
		mismatch += "_"
	}
	if src.Validate(mismatch) {
		t.Errorf("Validate(mismatch) = true, want false")
	}

	// Length-different input MUST NOT panic and MUST return false; the
	// length-padding scratch buffer is the path under test.
	if src.Validate("short") {
		t.Errorf("Validate(short) = true, want false")
	}
	if src.Validate(strings.Repeat("z", len(current)*4)) {
		t.Errorf("Validate(long) = true, want false")
	}

	// Positive-path sanity: the constant-time helper still returns
	// true on an exact match.
	if !src.Validate(current) {
		t.Errorf("Validate(current) = false, want true")
	}
}
