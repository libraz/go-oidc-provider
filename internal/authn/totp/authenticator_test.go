package totp_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
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
	data, ok := step.Prompt.Data.(interaction.TOTPPromptData)
	if !ok {
		t.Fatalf("Prompt.Data type = %T, want interaction.TOTPPromptData", step.Prompt.Data)
	}
	if data.AttemptsRemaining != 30 {
		t.Errorf("AttemptsRemaining = %d, want 30", data.AttemptsRemaining)
	}
	if len(step.Prompt.Inputs) != 1 || step.Prompt.Inputs[0].Name != totp.CodeFieldName {
		t.Errorf("Inputs = %+v, want one entry named %q", step.Prompt.Inputs, totp.CodeFieldName)
	}
}

// TestAuthenticator_BeginRequiresSubject pins half of the
// "TOTP cannot run without primary-factor proof" invariant: the
// adapter rejects Begin when the orchestrator has not yet bound a
// subject. The orchestrator only binds Subject after the primary
// (subject-identifying) factor completes, so this gate guarantees
// that no caller can drive the TOTP factor from a fresh chain.
//
// Tracks:
//   - GHSA-9r3w-4j8q-pw98 (cal.com, 2024-04, CVSS 9.8) — TRPC
//     verifyTwoFactor accepted (email, password, totpCode) and
//     returned a session without verifying the password. Same class
//     as CWE-287 "Improper Authentication".
//   - GHSA-5jfq-x6xp-7rw2 (Keycloak, 2024-09, CVSS 6.8) — two-factor
//     authentication bypass via direct OTP submission. Same
//     structural property: every TOTP path needs primary-factor proof.
//
// The matching chain-isolation test is
// authn.TestLoginFlowTOTPRequiresPrimary, which pins the orchestrator
// half of the invariant (TOTP step is only reachable after Primary's
// CompletedStepKinds entry lands).
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

func TestAuthenticator_BeginUsesClockForLockExpiry(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	rec, err := f.store.Get(context.Background(), f.subject)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	rec.LockedUntil = f.clock.t.Add(-time.Minute)
	if err := f.store.Put(context.Background(), rec); err != nil {
		t.Fatalf("Put: %v", err)
	}

	step, err := f.adapter.Begin(context.Background(), op.BeginInput{
		Subject:  f.subject,
		AuthTime: f.clock.t.Add(-time.Hour),
	})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if step.Prompt == nil {
		t.Fatalf("Begin returned no prompt: %+v", step)
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
		Submission: interaction.FormSubmission{Values: map[string]string{totp.CodeFieldName: code}},
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
		Submission: interaction.FormSubmission{Values: map[string]string{totp.CodeFieldName: "000000"}},
	})
	if err != nil {
		t.Fatalf("Continue returned err = %v, want nil for wrong code", err)
	}
	if step.Prompt == nil {
		t.Fatalf("expected re-emit Prompt, got %+v", step)
	}
	data, ok := step.Prompt.Data.(interaction.TOTPPromptData)
	if !ok {
		t.Fatalf("Prompt.Data type = %T, want interaction.TOTPPromptData", step.Prompt.Data)
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
		Submission: interaction.FormSubmission{Values: map[string]string{totp.CodeFieldName: "000000"}},
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
		Submission: interaction.FormSubmission{Values: map[string]string{}},
	})
	if !errors.Is(err, totp.ErrCodeMissing) {
		t.Fatalf("err = %v, want ErrCodeMissing", err)
	}
}

// TestAuthenticator_ContinueRequiresSubject is the Continue-side pair
// of TestAuthenticator_BeginRequiresSubject: even if a malicious
// caller fabricated a TOTP submission, the adapter rejects it without
// a bound subject. Combined with the orchestrator's StateRef-tagging
// invariant (a TOTP-tagged StateRef is only emitted after Primary
// completes) this gives two layers of defence against the cal.com /
// Keycloak primary-skip class.
//
// Tracks: GHSA-9r3w-4j8q-pw98, GHSA-5jfq-x6xp-7rw2 — see
// TestAuthenticator_BeginRequiresSubject for the threat model.
func TestAuthenticator_ContinueRequiresSubject(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	_, err := f.adapter.Continue(context.Background(), op.ContinueInput{
		AuthTime:   f.authTime,
		Submission: interaction.FormSubmission{Values: map[string]string{totp.CodeFieldName: "123456"}},
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

// acceptBlockedTOTPStore wraps a real [store.TOTPStore] and delegates all
// methods except Accept. When blockAccept is true, Accept returns
// [store.ErrAlreadyConsumed] unconditionally, simulating a concurrent
// verification winning the CAS race against the current request.
type acceptBlockedTOTPStore struct {
	inner       store.TOTPStore
	blockAccept bool
}

func (s *acceptBlockedTOTPStore) Get(ctx context.Context, subject string) (*store.TOTPRecord, error) {
	return s.inner.Get(ctx, subject)
}

func (s *acceptBlockedTOTPStore) Put(ctx context.Context, r *store.TOTPRecord) error {
	return s.inner.Put(ctx, r)
}

func (s *acceptBlockedTOTPStore) Accept(ctx context.Context, r *store.TOTPRecord) error {
	if s.blockAccept {
		return store.ErrAlreadyConsumed
	}
	return s.inner.Accept(ctx, r)
}

func (s *acceptBlockedTOTPStore) Delete(ctx context.Context, subject string) error {
	return s.inner.Delete(ctx, subject)
}

// TestAuthenticator_ContinueAcceptCASLossRePrompts pins the behaviour of
// the CAS-loss branch in Continue: when the store's Accept loses the
// compare-and-set race (another concurrent request already advanced the
// LastAcceptedStep counter), the authenticator MUST re-emit the TOTP
// prompt with nil error and MUST NOT produce an interaction.Result,
// ensuring no subject is authenticated through the losing request.
func TestAuthenticator_ContinueAcceptCASLossRePrompts(t *testing.T) {
	t.Parallel()

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

	realStore := inmem.New().TOTPs()
	rec := newRecord(t, codec, "user-alice", secret, clock.t.Add(-time.Hour))
	if err := realStore.Put(context.Background(), rec); err != nil {
		t.Fatalf("Put: %v", err)
	}

	blocked := &acceptBlockedTOTPStore{inner: realStore, blockAccept: true}
	adapter, err := totp.NewAuthenticator(verifier, blocked)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	code := totp.Code(secret, clock.t)
	step, err := adapter.Continue(context.Background(), op.ContinueInput{
		Subject:    "user-alice",
		AuthTime:   clock.t,
		Submission: interaction.FormSubmission{Values: map[string]string{totp.CodeFieldName: code}},
	})

	// Security invariant: the CAS-losing request must NOT authenticate the subject.
	if step.Result != nil {
		t.Errorf("CAS-loss path produced an authentication Result; no Result must be emitted: %+v", step.Result)
	}
	// The authenticator must re-prompt so the user can try again on
	// the next TOTP step rather than receiving a chain-fatal error.
	if err != nil {
		t.Fatalf("err = %v, want nil (re-prompt, not error)", err)
	}
	if step.Prompt == nil {
		t.Fatalf("expected re-prompt step, got %+v", step)
	}
	if step.Prompt.Type != totp.PromptType {
		t.Errorf("Prompt.Type = %q, want %q", step.Prompt.Type, totp.PromptType)
	}
}
