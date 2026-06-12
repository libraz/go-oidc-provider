package recovery_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/internal/authn/recovery"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// adapterFixture wires the adapter against a real verifier and the
// in-memory recovery store.
type adapterFixture struct {
	clock     *fakeClock
	store     store.RecoveryStore
	adapter   *recovery.Authenticator
	subject   string
	plaintext []string
	authTime  time.Time
}

func newAdapterFixture(t *testing.T) *adapterFixture {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)}
	verifier := &recovery.Verifier{Clock: clk}
	res, err := verifier.Generate(context.Background(), "user-alice")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	persisted := inmem.New().RecoveryCodes()
	if err := persisted.Put(context.Background(), res.Batch); err != nil {
		t.Fatalf("Put: %v", err)
	}
	adapter, err := recovery.NewAuthenticator(verifier, persisted)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return &adapterFixture{
		clock:     clk,
		store:     persisted,
		adapter:   adapter,
		subject:   "user-alice",
		plaintext: res.PlaintextCodes,
		authTime:  clk.t,
	}
}

func TestAuthenticator_Metadata(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	if got := f.adapter.Type(); got != op.FactorRecoveryCode {
		t.Errorf("Type() = %v, want %v", got, op.FactorRecoveryCode)
	}
	if got := f.adapter.AAL(); got != op.AAL2 {
		t.Errorf("AAL() = %v, want AAL2", got)
	}
	if got := f.adapter.AMR(); got != "otp" {
		t.Errorf("AMR() = %q, want otp", got)
	}
	prompts := f.adapter.Prompts()
	if len(prompts) != 1 || prompts[0] != recovery.PromptType {
		t.Errorf("Prompts() = %v, want [%s]", prompts, recovery.PromptType)
	}
}

func TestAuthenticator_BeginEmitsPromptWithFullSlots(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	step, err := f.adapter.Begin(context.Background(), op.BeginInput{
		Subject:  f.subject,
		AuthTime: f.authTime,
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if step.Prompt == nil {
		t.Fatalf("expected Prompt, got %+v", step)
	}
	data, ok := step.Prompt.Data.(interaction.RecoveryCodePromptData)
	if !ok {
		t.Fatalf("Prompt.Data type = %T, want interaction.RecoveryCodePromptData", step.Prompt.Data)
	}
	if data.AttemptsRemaining != 10 {
		t.Errorf("AttemptsRemaining = %d, want 10", data.AttemptsRemaining)
	}
}

func TestAuthenticator_BeginRequiresSubject(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	_, err := f.adapter.Begin(context.Background(), op.BeginInput{AuthTime: f.authTime})
	if !errors.Is(err, recovery.ErrSubjectRequired) {
		t.Fatalf("err = %v, want ErrSubjectRequired", err)
	}
}

func TestAuthenticator_BeginPropagatesNotFound(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	_, err := f.adapter.Begin(context.Background(), op.BeginInput{
		Subject:  "no-such-user",
		AuthTime: f.authTime,
	})
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestAuthenticator_CrossFactorLockoutSurfacesAsErrLocked(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	st := inmem.New()
	counter, err := lockout.New(st.AuthnLockouts(), nil)
	if err != nil {
		t.Fatalf("lockout.New: %v", err)
	}
	for i := range 30 {
		if _, err := counter.RecordFailure(context.Background(), f.subject); err != nil {
			t.Fatalf("RecordFailure %d: %v", i+1, err)
		}
	}
	auth := f.adapter.WithLockout(counter)

	_, err = auth.Begin(context.Background(), op.BeginInput{
		Subject:  f.subject,
		AuthTime: f.authTime,
	})
	if !errors.Is(err, recovery.ErrLocked) {
		t.Fatalf("Begin err=%v want ErrLocked", err)
	}
	_, err = auth.Continue(context.Background(), op.ContinueInput{
		Subject:  f.subject,
		AuthTime: f.authTime,
		Submission: interaction.FormSubmission{Values: map[string]string{
			recovery.CodeFieldName: "00000-00000",
		}},
	})
	if !errors.Is(err, recovery.ErrLocked) {
		t.Fatalf("Continue err=%v want ErrLocked", err)
	}
}

func TestAuthenticator_ContinueSuccessReturnsResultAndPersists(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	step, err := f.adapter.Continue(context.Background(), op.ContinueInput{
		Subject:    f.subject,
		AuthTime:   f.authTime,
		Submission: interaction.FormSubmission{Values: map[string]string{recovery.CodeFieldName: f.plaintext[2]}},
	})
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("expected Result, got %+v", step)
	}
	if step.Result.Subject != f.subject {
		t.Errorf("Subject = %q, want %q", step.Result.Subject, f.subject)
	}

	batch, err := f.store.Get(context.Background(), f.subject)
	if err != nil {
		t.Fatalf("Get after success: %v", err)
	}
	if batch.Codes[2].ConsumedAt.IsZero() {
		t.Error("ConsumedAt should be stamped on the matched slot")
	}
	// Other slots remain unconsumed.
	for i, c := range batch.Codes {
		if i == 2 {
			continue
		}
		if !c.ConsumedAt.IsZero() {
			t.Errorf("slot %d unexpectedly consumed", i)
		}
	}
}

func TestAuthenticator_ContinueWrongCodeReEmitsPromptWithoutConsuming(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	step, err := f.adapter.Continue(context.Background(), op.ContinueInput{
		Subject:    f.subject,
		AuthTime:   f.authTime,
		Submission: interaction.FormSubmission{Values: map[string]string{recovery.CodeFieldName: "WRONG-CODES"}},
	})
	if err != nil {
		t.Fatalf("Continue err = %v, want nil for invalid code", err)
	}
	if step.Prompt == nil {
		t.Fatalf("expected re-emit Prompt, got %+v", step)
	}
	data, ok := step.Prompt.Data.(interaction.RecoveryCodePromptData)
	if !ok {
		t.Fatalf("Prompt.Data type = %T, want interaction.RecoveryCodePromptData", step.Prompt.Data)
	}
	if data.AttemptsRemaining != 10 {
		t.Errorf("AttemptsRemaining = %d, want 10 (no slot consumed)", data.AttemptsRemaining)
	}

	batch, err := f.store.Get(context.Background(), f.subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	for i, c := range batch.Codes {
		if !c.ConsumedAt.IsZero() {
			t.Errorf("slot %d unexpectedly consumed", i)
		}
	}
}

func TestAuthenticator_ContinueAllConsumedReturnsError(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	for i := range f.plaintext {
		_, err := f.adapter.Continue(context.Background(), op.ContinueInput{
			Subject:    f.subject,
			AuthTime:   f.authTime,
			Submission: interaction.FormSubmission{Values: map[string]string{recovery.CodeFieldName: f.plaintext[i]}},
		})
		if err != nil {
			t.Fatalf("Continue %d: %v", i, err)
		}
	}
	_, err := f.adapter.Continue(context.Background(), op.ContinueInput{
		Subject:    f.subject,
		AuthTime:   f.authTime,
		Submission: interaction.FormSubmission{Values: map[string]string{recovery.CodeFieldName: f.plaintext[0]}},
	})
	if !errors.Is(err, recovery.ErrAllConsumed) {
		t.Fatalf("err = %v, want ErrAllConsumed", err)
	}
}

func TestAuthenticator_ContinueRequiresCodeAndSubject(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	_, err := f.adapter.Continue(context.Background(), op.ContinueInput{
		Subject:    f.subject,
		AuthTime:   f.authTime,
		Submission: interaction.FormSubmission{Values: map[string]string{}},
	})
	if !errors.Is(err, recovery.ErrCodeMissing) {
		t.Fatalf("missing code: err = %v, want ErrCodeMissing", err)
	}

	_, err = f.adapter.Continue(context.Background(), op.ContinueInput{
		AuthTime:   f.authTime,
		Submission: interaction.FormSubmission{Values: map[string]string{recovery.CodeFieldName: "SOMETHING"}},
	})
	if !errors.Is(err, recovery.ErrSubjectRequired) {
		t.Fatalf("missing subject: err = %v, want ErrSubjectRequired", err)
	}
}

func TestNewAuthenticator_RejectsNilArgs(t *testing.T) {
	t.Parallel()

	t.Run("nil verifier", func(t *testing.T) {
		t.Parallel()
		_, err := recovery.NewAuthenticator(nil, inmem.New().RecoveryCodes())
		if !errors.Is(err, recovery.ErrVerifierRequired) {
			t.Fatalf("err = %v, want ErrVerifierRequired", err)
		}
	})

	t.Run("nil store", func(t *testing.T) {
		t.Parallel()
		_, err := recovery.NewAuthenticator(&recovery.Verifier{}, nil)
		if !errors.Is(err, recovery.ErrStoreRequired) {
			t.Fatalf("err = %v, want ErrStoreRequired", err)
		}
	})
}
