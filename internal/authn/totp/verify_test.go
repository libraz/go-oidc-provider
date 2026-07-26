package totp_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// fakeClock returns a fixed instant. It is the test-side analogue of
// timex.SystemClock used to drive the brute-force counter rollover
// deterministically.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time { return c.t }

// newRecord builds a fresh TOTPRecord with secret encrypted under the
// supplied codec and confirmed at t. The Subject string doubles as the
// AAD bound into the GCM tag.
func newRecord(tb testing.TB, codec *totp.Codec, subject string, secret []byte, confirmedAt time.Time) *store.TOTPRecord {
	tb.Helper()
	blob, err := codec.Seal(secret, []byte(subject))
	if err != nil {
		tb.Fatalf("Seal: %v", err)
	}
	return &store.TOTPRecord{
		Subject:          subject,
		SecretCiphertext: blob,
		ConfirmedAt:      confirmedAt,
	}
}

// fixture wires a Verifier and a Record with the deterministic clock the
// brute-force tests share. The reference time is far enough into the
// future that the negative-Unix branch of step() is irrelevant.
type fixture struct {
	clock    *fakeClock
	verifier *totp.Verifier
	record   *store.TOTPRecord
	secret   []byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	codec, err := totp.NewCodec(newKey(t))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	clock := &fakeClock{t: time.Unix(1700000000, 0).UTC()}
	rec := newRecord(t, codec, "user-alice", secret, clock.t.Add(-time.Hour))
	return &fixture{
		clock: clock,
		verifier: &totp.Verifier{
			Clock: clock,
			Codec: codec,
		},
		record: rec,
		secret: secret,
	}
}

func TestVerify_HappyPath(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	code := totp.Code(f.secret, f.clock.t)

	res, err := f.verifier.Verify(context.Background(), f.record, code)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Outcome != totp.OutcomeSuccess {
		t.Errorf("outcome=%v want Success", res.Outcome)
	}
	if res.Record.FailedCount != 0 {
		t.Errorf("FailedCount=%d want 0", res.Record.FailedCount)
	}
	if !res.Record.LockedUntil.IsZero() {
		t.Errorf("LockedUntil=%v want zero", res.Record.LockedUntil)
	}
}

func TestVerify_AcceptsSkewWithinWindow(t *testing.T) {
	t.Parallel()

	for _, offset := range []time.Duration{-30 * time.Second, +30 * time.Second} {
		t.Run(offset.String(), func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			// Code computed at a step adjacent to the verifier's
			// "now" must still be accepted under the default skew.
			code := totp.Code(f.secret, f.clock.t.Add(offset))
			res, err := f.verifier.Verify(context.Background(), f.record, code)
			if err != nil {
				t.Fatalf("Verify offset=%v: %v", offset, err)
			}
			if res.Outcome != totp.OutcomeSuccess {
				t.Errorf("outcome=%v want Success", res.Outcome)
			}
		})
	}
}

func TestVerify_RejectsSkewOutsideWindow(t *testing.T) {
	t.Parallel()

	for _, offset := range []time.Duration{-60 * time.Second, +60 * time.Second} {
		t.Run(offset.String(), func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			code := totp.Code(f.secret, f.clock.t.Add(offset))
			_, err := f.verifier.Verify(context.Background(), f.record, code)
			if !errors.Is(err, totp.ErrWrongCode) {
				t.Errorf("offset=%v err=%v want ErrWrongCode", offset, err)
			}
		})
	}
}

func TestVerify_WrongCodeIncrementsCounter(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	res, err := f.verifier.Verify(context.Background(), f.record, "000000")
	if !errors.Is(err, totp.ErrWrongCode) {
		t.Fatalf("err=%v want ErrWrongCode", err)
	}
	if res.Outcome != totp.OutcomeWrongCode {
		t.Errorf("outcome=%v want WrongCode", res.Outcome)
	}
	if res.Record.FailedCount != 1 {
		t.Errorf("FailedCount=%d want 1", res.Record.FailedCount)
	}
	if res.Record.FirstFailureAt.IsZero() {
		t.Errorf("FirstFailureAt=zero want %v", f.clock.t)
	}
}

func TestVerify_LocksAtThirtyFailures(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	const target = 30
	for i := range target {
		attempt := i + 1
		_, err := f.verifier.Verify(context.Background(), f.record, "000000")
		if attempt < target {
			if !errors.Is(err, totp.ErrWrongCode) {
				t.Fatalf("attempt %d err=%v want ErrWrongCode", attempt, err)
			}
			if !f.record.LockedUntil.IsZero() {
				t.Fatalf("attempt %d: LockedUntil set prematurely (%v)", attempt, f.record.LockedUntil)
			}
			continue
		}
		// Attempt 30 stamps the 1-hour lock but does NOT escalate to
		// ResetRequired (that is reserved for >=90).
		if !errors.Is(err, totp.ErrWrongCode) {
			t.Fatalf("attempt %d err=%v want ErrWrongCode", attempt, err)
		}
		want := f.clock.t.Add(time.Hour)
		if !f.record.LockedUntil.Equal(want) {
			t.Errorf("LockedUntil=%v want %v", f.record.LockedUntil, want)
		}
	}
}

func TestVerify_RejectsWhileLocked(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.record.LockedUntil = f.clock.t.Add(10 * time.Minute)

	// Even the correct code is rejected with ErrLocked while the lock
	// is in effect.
	correct := totp.Code(f.secret, f.clock.t)
	res, err := f.verifier.Verify(context.Background(), f.record, correct)
	if !errors.Is(err, totp.ErrLocked) {
		t.Fatalf("err=%v want ErrLocked", err)
	}
	if res.Outcome != totp.OutcomeLocked {
		t.Errorf("outcome=%v want Locked", res.Outcome)
	}
}

func TestVerify_LockExpiresAndCorrectCodeWins(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.record.LockedUntil = f.clock.t.Add(-time.Minute)
	f.record.FailedCount = 30

	correct := totp.Code(f.secret, f.clock.t)
	res, err := f.verifier.Verify(context.Background(), f.record, correct)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Outcome != totp.OutcomeSuccess {
		t.Errorf("outcome=%v want Success", res.Outcome)
	}
	if res.Record.FailedCount != 0 {
		t.Errorf("FailedCount=%d want 0", res.Record.FailedCount)
	}
}

func TestVerify_ResetRequiredAtNinety(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	// Pre-load the record at the brink of the long-lock threshold so
	// the test doesn't loop 90 times against the verifier (each
	// failure mutates the record's clock window once anyway).
	f.record.FailedCount = 89
	f.record.FirstFailureAt = f.clock.t.Add(-time.Hour)

	res, err := f.verifier.Verify(context.Background(), f.record, "000000")
	if !errors.Is(err, totp.ErrResetRequired) {
		t.Fatalf("err=%v want ErrResetRequired", err)
	}
	if res.Outcome != totp.OutcomeResetRequired {
		t.Errorf("outcome=%v want ResetRequired", res.Outcome)
	}
	want := f.clock.t.Add(24 * time.Hour)
	if !res.Record.LockedUntil.Equal(want) {
		t.Errorf("LockedUntil=%v want %v", res.Record.LockedUntil, want)
	}
}

func TestVerify_SuccessClearsCounter(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.record.FailedCount = 5
	f.record.FirstFailureAt = f.clock.t.Add(-time.Hour)
	f.record.LockedUntil = time.Time{}

	correct := totp.Code(f.secret, f.clock.t)
	res, err := f.verifier.Verify(context.Background(), f.record, correct)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Record.FailedCount != 0 {
		t.Errorf("FailedCount=%d want 0", res.Record.FailedCount)
	}
	if !res.Record.FirstFailureAt.IsZero() {
		t.Errorf("FirstFailureAt=%v want zero", res.Record.FirstFailureAt)
	}
}

func TestVerify_TwentyFourHourRolloverResetsCounter(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	// Stale window: a single failure recorded > 24h ago. The next
	// failure must restart the counter at 1, not at 2.
	f.record.FailedCount = 12
	f.record.FirstFailureAt = f.clock.t.Add(-25 * time.Hour)

	res, err := f.verifier.Verify(context.Background(), f.record, "000000")
	if !errors.Is(err, totp.ErrWrongCode) {
		t.Fatalf("err=%v want ErrWrongCode", err)
	}
	if res.Record.FailedCount != 1 {
		t.Errorf("FailedCount=%d want 1 after rollover", res.Record.FailedCount)
	}
	if !res.Record.FirstFailureAt.Equal(f.clock.t) {
		t.Errorf("FirstFailureAt=%v want %v", res.Record.FirstFailureAt, f.clock.t)
	}
}

func TestVerify_UnconfirmedRecordRejected(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.record.ConfirmedAt = time.Time{}

	correct := totp.Code(f.secret, f.clock.t)
	if _, err := f.verifier.Verify(context.Background(), f.record, correct); !errors.Is(err, totp.ErrNotConfirmed) {
		t.Errorf("err=%v want ErrNotConfirmed", err)
	}
}

func TestVerify_NilRecord(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	if _, err := f.verifier.Verify(context.Background(), nil, "000000"); err == nil {
		t.Error("Verify(nil) returned nil error")
	}
}

// TestVerify_ReplaysSameStepRejected asserts the replay defence: a
// second verify with the same code within the same 30s window is
// rejected as ErrWrongCode without incrementing the brute-force
// counter, while a code computed at a strictly later step is accepted
// normally.
//
// Tracks: CVE-2026-33473 (Vikunja), and the same class in
// CVE-2025-43798 (Liferay) and CVE-2021-43177 (devise-two-factor) — a
// TOTP code was checked against the current time step and nothing
// consumed it, so it kept authenticating for the rest of its window.
// Anyone who saw a code once (over a shoulder, in a phished form, in a
// log) could reuse it, which reduces the factor to a shared secret with
// a 30-second lifetime. Consuming the step on acceptance is what makes
// the code single-use; the counter assertion matters too, since a
// replay that advanced the brute-force counter would let a captured
// code be used to lock the account out instead.
func TestVerify_ReplaysSameStepRejected(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	code := totp.Code(f.secret, f.clock.t)

	res, err := f.verifier.Verify(context.Background(), f.record, code)
	if err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	if res.Outcome != totp.OutcomeSuccess {
		t.Fatalf("first outcome=%v want Success", res.Outcome)
	}
	// Snapshot the step now: Result.Record aliases the input pointer
	// so subsequent Verify calls would mutate this value through the
	// alias and the comparison further down would silently equal.
	firstStep := res.Record.LastAcceptedStep
	if firstStep == 0 {
		t.Errorf("LastAcceptedStep=0 after success; replay defence disabled")
	}

	// Replay the same code at the same wall-clock time. Without the
	// LastAcceptedStep guard the verifier would happily match again.
	res2, err2 := f.verifier.Verify(context.Background(), f.record, code)
	if !errors.Is(err2, totp.ErrWrongCode) {
		t.Fatalf("replay err=%v want ErrWrongCode", err2)
	}
	if res2.Record.FailedCount != 0 {
		t.Errorf("FailedCount=%d want 0 (replay must not punish)", res2.Record.FailedCount)
	}

	// Advance the clock to the next step boundary and verify a freshly
	// computed code redeems normally.
	f.clock.t = f.clock.t.Add(31 * time.Second)
	next := totp.Code(f.secret, f.clock.t)
	res3, err3 := f.verifier.Verify(context.Background(), f.record, next)
	if err3 != nil {
		t.Fatalf("next-step Verify: %v", err3)
	}
	if res3.Outcome != totp.OutcomeSuccess {
		t.Errorf("next-step outcome=%v want Success", res3.Outcome)
	}
	if res3.Record.LastAcceptedStep <= firstStep {
		t.Errorf("LastAcceptedStep did not advance: was=%d now=%d",
			firstStep, res3.Record.LastAcceptedStep)
	}
}

func TestVerify_DefaultsClockToSystem(t *testing.T) {
	t.Parallel()

	codec, err := totp.NewCodec(newKey(t))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	now := timex.SystemClock.Now()
	rec := newRecord(t, codec, "user-alice", secret, now.Add(-time.Hour))

	// The default-clock verifier reads time.Now() twice (once to compute
	// the candidate code, once inside Verify). The skew window absorbs
	// the gap so long as the test does not run for more than 30s; in
	// practice Verify finishes in microseconds.
	v := &totp.Verifier{Codec: codec}
	correct := totp.Code(secret, now)
	res, err := v.Verify(context.Background(), rec, correct)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Outcome != totp.OutcomeSuccess {
		t.Errorf("outcome=%v want Success", res.Outcome)
	}
}
