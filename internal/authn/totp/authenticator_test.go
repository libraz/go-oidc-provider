package totp_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// adapterFixture wires the adapter against a real verifier and the
// in-memory TOTP store. Tests may mutate the persisted record between
// calls to exercise the lockout / reset paths.
type adapterFixture struct {
	clock    *fakeClock
	codec    *totp.Codec
	store    store.TOTPStore
	adapter  *totp.Authenticator
	verifier *totp.Verifier
	subject  string
	secret   []byte
	authTime time.Time
}

func newAdapterFixture(t *testing.T) *adapterFixture {
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
	verifier := &totp.Verifier{Clock: clock, Codec: codec}
	persisted := inmem.New().TOTPs()
	rec := newRecord(t, codec, "user-alice", secret, clock.t.Add(-time.Hour))
	if err := persisted.Put(context.Background(), rec); err != nil {
		t.Fatalf("Put: %v", err)
	}
	adapter, err := totp.NewAuthenticator(verifier, persisted)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return &adapterFixture{
		clock:    clock,
		codec:    codec,
		store:    persisted,
		adapter:  adapter,
		verifier: verifier,
		subject:  "user-alice",
		secret:   secret,
		authTime: clock.t,
	}
}

func TestAuthenticator_Metadata(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	if got := f.adapter.Type(); got != op.FactorTOTP {
		t.Errorf("Type() = %v, want %v", got, op.FactorTOTP)
	}
	if got := f.adapter.AAL(); got != op.AAL2 {
		t.Errorf("AAL() = %v, want AAL2", got)
	}
	if got := f.adapter.AMR(); got != "otp" {
		t.Errorf("AMR() = %q, want otp", got)
	}
	prompts := f.adapter.Prompts()
	if len(prompts) != 1 || prompts[0] != totp.PromptType {
		t.Errorf("Prompts() = %v, want [%s]", prompts, totp.PromptType)
	}
}

func TestAuthenticator_BeginEmitsPromptWithFullAttempts(t *testing.T) {
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
		t.Fatalf("Begin returned no prompt: %+v", step)
	}
	if step.Prompt.Type != totp.PromptType {
		t.Errorf("Prompt.Type = %q, want %q", step.Prompt.Type, totp.PromptType)
	}
	data, ok := step.Prompt.Data.(op.TOTPPromptData)
	if !ok {
		t.Fatalf("Prompt.Data type = %T, want op.TOTPPromptData", step.Prompt.Data)
	}
	if data.AttemptsRemaining != 30 {
		t.Errorf("AttemptsRemaining = %d, want 30", data.AttemptsRemaining)
	}
	if len(step.Prompt.Inputs) != 1 || step.Prompt.Inputs[0].Name != totp.CodeFieldName {
		t.Errorf("Inputs = %+v, want one entry named %q", step.Prompt.Inputs, totp.CodeFieldName)
	}
}

func TestAuthenticator_BeginRequiresSubject(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	_, err := f.adapter.Begin(context.Background(), op.BeginInput{AuthTime: f.authTime})
	if !errors.Is(err, totp.ErrSubjectRequired) {
		t.Fatalf("err = %v, want ErrSubjectRequired", err)
	}
}

func TestAuthenticator_BeginRejectsWhileLocked(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	rec, err := f.store.Get(context.Background(), f.subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	rec.LockedUntil = f.authTime.Add(time.Hour)
	if err := f.store.Put(context.Background(), rec); err != nil {
		t.Fatalf("Put: %v", err)
	}

	_, err = f.adapter.Begin(context.Background(), op.BeginInput{
		Subject:  f.subject,
		AuthTime: f.authTime,
	})
	if !errors.Is(err, totp.ErrLocked) {
		t.Fatalf("err = %v, want ErrLocked", err)
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

func TestAuthenticator_ContinueSuccessReturnsResult(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	code := totp.Code(f.secret, f.authTime)

	step, err := f.adapter.Continue(context.Background(), op.ContinueInput{
		Subject:    f.subject,
		AuthTime:   f.authTime,
		Submission: op.FormSubmission{Values: map[string]string{totp.CodeFieldName: code}},
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
	if !step.Result.AuthTime.Equal(f.authTime) {
		t.Errorf("AuthTime = %v, want %v", step.Result.AuthTime, f.authTime)
	}

	rec, err := f.store.Get(context.Background(), f.subject)
	if err != nil {
		t.Fatalf("Get after success: %v", err)
	}
	if rec.FailedCount != 0 {
		t.Errorf("FailedCount = %d, want 0", rec.FailedCount)
	}
}

func TestAuthenticator_ContinueWrongCodeReEmitsPrompt(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	step, err := f.adapter.Continue(context.Background(), op.ContinueInput{
		Subject:    f.subject,
		AuthTime:   f.authTime,
		Submission: op.FormSubmission{Values: map[string]string{totp.CodeFieldName: "000000"}},
	})
	if err != nil {
		t.Fatalf("Continue returned err = %v, want nil for wrong code", err)
	}
	if step.Prompt == nil {
		t.Fatalf("expected re-emit Prompt, got %+v", step)
	}
	data, ok := step.Prompt.Data.(op.TOTPPromptData)
	if !ok {
		t.Fatalf("Prompt.Data type = %T, want op.TOTPPromptData", step.Prompt.Data)
	}
	if data.AttemptsRemaining != 29 {
		t.Errorf("AttemptsRemaining = %d, want 29 after one miss", data.AttemptsRemaining)
	}

	rec, err := f.store.Get(context.Background(), f.subject)
	if err != nil {
		t.Fatalf("Get after miss: %v", err)
	}
	if rec.FailedCount != 1 {
		t.Errorf("FailedCount = %d, want 1", rec.FailedCount)
	}
}

func TestAuthenticator_ContinueLockReturnsError(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	rec, err := f.store.Get(context.Background(), f.subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	rec.FailedCount = 89
	rec.FirstFailureAt = f.authTime.Add(-time.Minute)
	if err := f.store.Put(context.Background(), rec); err != nil {
		t.Fatalf("Put: %v", err)
	}

	_, err = f.adapter.Continue(context.Background(), op.ContinueInput{
		Subject:    f.subject,
		AuthTime:   f.authTime,
		Submission: op.FormSubmission{Values: map[string]string{totp.CodeFieldName: "000000"}},
	})
	if !errors.Is(err, totp.ErrResetRequired) {
		t.Fatalf("err = %v, want ErrResetRequired", err)
	}
	rec, err = f.store.Get(context.Background(), f.subject)
	if err != nil {
		t.Fatalf("Get after lock: %v", err)
	}
	if rec.LockedUntil.IsZero() {
		t.Error("LockedUntil should be stamped after reset trigger")
	}
}

func TestAuthenticator_ContinueRequiresCodeField(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	_, err := f.adapter.Continue(context.Background(), op.ContinueInput{
		Subject:    f.subject,
		AuthTime:   f.authTime,
		Submission: op.FormSubmission{Values: map[string]string{}},
	})
	if !errors.Is(err, totp.ErrCodeMissing) {
		t.Fatalf("err = %v, want ErrCodeMissing", err)
	}
}

func TestAuthenticator_ContinueRequiresSubject(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	_, err := f.adapter.Continue(context.Background(), op.ContinueInput{
		AuthTime:   f.authTime,
		Submission: op.FormSubmission{Values: map[string]string{totp.CodeFieldName: "123456"}},
	})
	if !errors.Is(err, totp.ErrSubjectRequired) {
		t.Fatalf("err = %v, want ErrSubjectRequired", err)
	}
}

func TestNewAuthenticator_RejectsNilArgs(t *testing.T) {
	t.Parallel()

	t.Run("nil verifier", func(t *testing.T) {
		t.Parallel()
		_, err := totp.NewAuthenticator(nil, inmem.New().TOTPs())
		if !errors.Is(err, totp.ErrVerifierRequired) {
			t.Fatalf("err = %v, want ErrVerifierRequired", err)
		}
	})

	t.Run("nil store", func(t *testing.T) {
		t.Parallel()
		codec, err := totp.NewCodec(newKey(t))
		if err != nil {
			t.Fatalf("NewCodec: %v", err)
		}
		_, err = totp.NewAuthenticator(&totp.Verifier{Codec: codec}, nil)
		if !errors.Is(err, totp.ErrStoreRequired) {
			t.Fatalf("err = %v, want ErrStoreRequired", err)
		}
	})
}
