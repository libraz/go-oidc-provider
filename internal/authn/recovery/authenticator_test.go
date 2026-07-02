package recovery_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
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

func TestAuthenticator_ContinueWrongCodeReturnsRetryWithoutConsuming(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	step, err := f.adapter.Continue(context.Background(), op.ContinueInput{
		Subject:    f.subject,
		AuthTime:   f.authTime,
		Submission: interaction.FormSubmission{Values: map[string]string{recovery.CodeFieldName: "WRONG-CODES"}},
	})
	// A wrong code must route through ErrFactorRetry so the orchestrator
	// observes the failure and advances the brute-force counter, rather
	// than silently re-emitting the prompt.
	if !errors.Is(err, recovery.ErrRetry) {
		t.Fatalf("Continue err = %v, want recovery.ErrRetry", err)
	}
	if !errors.Is(err, authn.ErrFactorRetry) {
		t.Fatalf("Continue err = %v, want to wrap authn.ErrFactorRetry", err)
	}
	if step.Prompt != nil || step.Result != nil {
		t.Fatalf("expected empty step on retry error, got %+v", step)
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

// consumeBlockedRecoveryStore wraps a real [store.RecoveryStore] and delegates
// all methods except Consume. When blockConsume is true, Consume returns
// [store.ErrAlreadyConsumed] unconditionally, simulating a concurrent
// redemption winning the CAS race against the current request.
type consumeBlockedRecoveryStore struct {
	inner        store.RecoveryStore
	blockConsume bool
}

func (s *consumeBlockedRecoveryStore) Get(ctx context.Context, subject string) (*store.RecoveryBatch, error) {
	return s.inner.Get(ctx, subject)
}

func (s *consumeBlockedRecoveryStore) Put(ctx context.Context, b *store.RecoveryBatch) error {
	return s.inner.Put(ctx, b)
}

func (s *consumeBlockedRecoveryStore) Consume(_ context.Context, _ *store.RecoveryBatch, _ int) error {
	if s.blockConsume {
		return store.ErrAlreadyConsumed
	}
	return nil
}

func (s *consumeBlockedRecoveryStore) Delete(ctx context.Context, subject string) error {
	return s.inner.Delete(ctx, subject)
}

// TestAuthenticator_ContinueConsumeCASLossRePrompts pins the behaviour of
// the CAS-loss branch in Continue: when the store's Consume loses the
// compare-and-set race (another concurrent request already stamped ConsumedAt
// on the same slot), the authenticator MUST re-emit the recovery-code prompt
// with nil error and MUST NOT produce an interaction.Result, ensuring no
// subject is authenticated through the losing request.
func TestAuthenticator_ContinueConsumeCASLossRePrompts(t *testing.T) {
	t.Parallel()

	clk := &fakeClock{t: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)}
	verifier := &recovery.Verifier{Clock: clk}
	res, err := verifier.Generate(context.Background(), "user-alice")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	backing := inmem.New().RecoveryCodes()
	if err := backing.Put(context.Background(), res.Batch); err != nil {
		t.Fatalf("Put: %v", err)
	}

	blocked := &consumeBlockedRecoveryStore{inner: backing, blockConsume: true}
	adapter, err := recovery.NewAuthenticator(verifier, blocked)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	// Use a valid plaintext code. The verifier will match it and stamp
	// the in-memory batch copy, then the store's Consume returns
	// ErrAlreadyConsumed (simulating a concurrent winner).
	step, err := adapter.Continue(context.Background(), op.ContinueInput{
		Subject:    "user-alice",
		AuthTime:   clk.t,
		Submission: interaction.FormSubmission{Values: map[string]string{recovery.CodeFieldName: res.PlaintextCodes[0]}},
	})

	// Security invariant: the CAS-losing request must NOT authenticate the subject.
	if step.Result != nil {
		t.Errorf("CAS-loss path produced an authentication Result; no Result must be emitted: %+v", step.Result)
	}
	// The authenticator must re-prompt so the user can try again rather
	// than receiving a chain-fatal error.
	if err != nil {
		t.Fatalf("err = %v, want nil (re-prompt, not error)", err)
	}
	if step.Prompt == nil {
		t.Fatalf("expected re-prompt step, got %+v", step)
	}
	if step.Prompt.Type != recovery.PromptType {
		t.Errorf("Prompt.Type = %q, want %q", step.Prompt.Type, recovery.PromptType)
	}
}
