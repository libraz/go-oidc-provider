package authn_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// lockoutStepFixture wraps a scripted factor with a counter on the
// in-memory lockout store.
type lockoutStepFixture struct {
	counter *lockout.Counter
	wrapped op.Authenticator
	begins  atomic.Int32
	// next scripts the wrapped factor's Continue.
	next func() (interaction.Step, error)
}

func newLockoutStepFixture(t *testing.T) *lockoutStepFixture {
	t.Helper()
	clock := &lockoutClock{t: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)}
	counter, err := lockout.New(inmem.New(inmem.WithClock(clock)).AuthnLockouts(), clock)
	if err != nil {
		t.Fatalf("lockout.New: %v", err)
	}
	f := &lockoutStepFixture{counter: counter}
	inner := &stubAuthenticator{
		typeID:  "myorg.sms",
		aal:     op.AAL2,
		prompts: []string{"myorg.sms"},
		beginFn: func(context.Context, op.BeginInput) (interaction.Step, error) {
			f.begins.Add(1)
			return interaction.Step{Prompt: &interaction.Prompt{Type: "myorg.sms"}}, nil
		},
		continueFn: func(context.Context, op.ContinueInput) (interaction.Step, error) {
			return f.next()
		},
	}
	f.wrapped = authn.WithLockoutCounter(inner, counter)
	return f
}

func (f *lockoutStepFixture) fail(t *testing.T, n int) {
	t.Helper()
	for range n {
		if _, err := f.counter.RecordFailure(context.Background(), lockoutSubject); err != nil {
			t.Fatalf("RecordFailure: %v", err)
		}
	}
}

func (f *lockoutStepFixture) remaining(t *testing.T) int {
	t.Helper()
	n, err := f.counter.RemainingAttempts(context.Background(), lockoutSubject)
	if err != nil {
		t.Fatalf("RemainingAttempts: %v", err)
	}
	return n
}

func (f *lockoutStepFixture) submit() (interaction.Step, error) {
	return f.wrapped.Continue(context.Background(), op.ContinueInput{Subject: lockoutSubject})
}

func TestLockoutStep_LockedRefusesBegin(t *testing.T) {
	t.Parallel()

	f := newLockoutStepFixture(t)
	f.next = func() (interaction.Step, error) {
		t.Error("Continue reached the wrapped factor while locked")
		return interaction.Step{}, nil
	}
	f.fail(t, 30)
	if _, err := f.wrapped.Begin(context.Background(), op.BeginInput{Subject: lockoutSubject}); !errors.Is(err, authn.ErrFactorLocked) {
		t.Fatalf("Begin err = %v, want ErrFactorLocked", err)
	}
	if n := f.begins.Load(); n != 0 {
		t.Errorf("wrapped Begin ran %d times while locked, want 0", n)
	}
	if _, err := f.submit(); !errors.Is(err, authn.ErrFactorLocked) {
		t.Fatalf("Continue err = %v, want ErrFactorLocked", err)
	}
}

func TestLockoutStep_RetryCounts(t *testing.T) {
	t.Parallel()

	f := newLockoutStepFixture(t)
	reprompt := &interaction.Prompt{Type: "myorg.sms"}
	retry := fmt.Errorf("wrong code: %w", authn.ErrFactorRetry)

	f.next = func() (interaction.Step, error) { return interaction.Step{Prompt: reprompt}, retry }
	step, err := f.submit()
	if !errors.Is(err, authn.ErrFactorRetry) || step.Prompt != reprompt {
		t.Fatalf("Continue = %+v, %v; want the re-prompt and the retry passed through", step, err)
	}
	if n := f.remaining(t); n != 29 {
		t.Errorf("remaining after a re-prompting retry = %d, want 29", n)
	}

	f.next = func() (interaction.Step, error) { return interaction.Step{}, retry }
	if _, err := f.submit(); !errors.Is(err, authn.ErrFactorRetry) {
		t.Fatalf("Continue err = %v, want the retry", err)
	}
	if n := f.remaining(t); n != 28 {
		t.Errorf("remaining after a plain retry = %d, want 28", n)
	}

	f.next = func() (interaction.Step, error) { return interaction.Step{}, errors.New("backend down") }
	if _, err := f.submit(); err == nil {
		t.Fatal("Continue err = nil, want the backend error")
	}
	if n := f.remaining(t); n != 28 {
		t.Errorf("remaining after a fault = %d, want 28 (faults are not guesses)", n)
	}
}

func TestLockoutStep_EngagingRetryEndsAttempt(t *testing.T) {
	t.Parallel()

	f := newLockoutStepFixture(t)
	f.fail(t, 29)
	f.next = func() (interaction.Step, error) {
		return interaction.Step{Prompt: &interaction.Prompt{Type: "myorg.sms"}}, fmt.Errorf("wrong code: %w", authn.ErrFactorRetry)
	}
	step, err := f.submit()
	if !errors.Is(err, authn.ErrFactorLocked) || !errors.Is(err, authn.ErrCredentialRejected) {
		t.Fatalf("err = %v, want ErrFactorLocked and ErrCredentialRejected", err)
	}
	if step.Prompt != nil {
		t.Errorf("prompt = %+v, want none once the lock engaged", step.Prompt)
	}
}

func TestLockoutStep_ResultResets(t *testing.T) {
	t.Parallel()

	f := newLockoutStepFixture(t)
	f.fail(t, 2)
	f.next = func() (interaction.Step, error) {
		return interaction.Step{Result: &interaction.Result{Subject: lockoutSubject}}, nil
	}
	if _, err := f.submit(); err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if n := f.remaining(t); n != 30 {
		t.Errorf("remaining after success = %d, want 30", n)
	}
}

func TestLockoutStep_PreservesOptionalInterfaces(t *testing.T) {
	t.Parallel()

	counter, err := lockout.New(inmem.New().AuthnLockouts(), &lockoutClock{t: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("lockout.New: %v", err)
	}
	prober := probed(op.FactorTOTP, true)
	wrapped := authn.WithLockoutCounter(prober, counter)
	p, ok := wrapped.(authn.EnrollmentProber)
	if !ok {
		t.Fatal("wrapped prober lost EnrollmentProber")
	}
	if enrolled, err := p.Enrolled(context.Background(), lockoutSubject); err != nil || !enrolled || prober.probes.Load() != 1 {
		t.Errorf("Enrolled = %v, %v (probes %d); want the wrapped answer", enrolled, err, prober.probes.Load())
	}
	if wrapped.Type() != op.FactorTOTP || wrapped.AAL() != op.AAL2 {
		t.Errorf("Type/AAL = %v/%v, want the wrapped values", wrapped.Type(), wrapped.AAL())
	}

	plain := authn.WithLockoutCounter(successAuth(op.FactorTOTP, op.AAL2, "otp", lockoutSubject), counter)
	if _, ok := plain.(authn.EnrollmentProber); ok {
		t.Error("wrapper of a non-prober claims EnrollmentProber")
	}

	unwrapped := successAuth(op.FactorTOTP, op.AAL2, "otp", lockoutSubject)
	if got := authn.WithLockoutCounter(unwrapped, nil); got != op.Authenticator(unwrapped) {
		t.Error("a nil counter did not return the authenticator unchanged")
	}
}
