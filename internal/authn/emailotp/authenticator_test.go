package emailotp_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/emailotp"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

type recordingMailer struct {
	mu   sync.Mutex
	last *emailotp.Message
	n    int
	err  error
}

func (m *recordingMailer) Send(_ context.Context, msg emailotp.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	cp := msg
	m.last = &cp
	m.n++
	return nil
}

func (m *recordingMailer) snapshot() (*emailotp.Message, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.last, m.n
}

type fakeUsers struct {
	users map[string]*store.User
}

func (u *fakeUsers) FindBySubject(_ context.Context, sub string) (*store.User, error) {
	if u, ok := u.users[sub]; ok {
		return u, nil
	}
	return nil, store.ErrNotFound
}

func newFixture(t *testing.T, now time.Time) (*emailotp.Authenticator, *recordingMailer, store.EmailOTPStore) {
	t.Helper()
	clock := &emailotp.FakeClock{T: now}
	st := inmem.New(inmem.WithClock(clock))
	users := &fakeUsers{
		users: map[string]*store.User{
			"sub-1": {Subject: "sub-1", Claims: map[string]any{"email": "alice@example.com"}},
		},
	}
	mailer := &recordingMailer{}
	a, err := emailotp.NewAuthenticator(emailotp.Config{
		Mailer: mailer,
		Store:  st.EmailOTPs(),
		Users:  users,
		Clock:  clock,
		// Disable the H-E3 latency pad: the FakeClock never moves
		// during a real-time time.Sleep, so a non-zero pad would
		// inflate every test run by the configured duration.
		SendLatencyPad: -1,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return a, mailer, st.EmailOTPs()
}

func TestNewAuthenticatorRequiresDeps(t *testing.T) {
	t.Parallel()
	users := &fakeUsers{}
	st := inmem.New().EmailOTPs()
	mailer := emailotp.MailerFunc(func(_ context.Context, _ emailotp.Message) error { return nil })

	if _, err := emailotp.NewAuthenticator(emailotp.Config{Store: st, Users: users}); !errors.Is(err, emailotp.ErrMailerRequired) {
		t.Errorf("missing Mailer: err = %v, want ErrMailerRequired", err)
	}
	if _, err := emailotp.NewAuthenticator(emailotp.Config{Mailer: mailer, Users: users}); !errors.Is(err, emailotp.ErrStoreRequired) {
		t.Errorf("missing Store: err = %v, want ErrStoreRequired", err)
	}
	if _, err := emailotp.NewAuthenticator(emailotp.Config{Mailer: mailer, Store: st}); !errors.Is(err, emailotp.ErrUsersRequired) {
		t.Errorf("missing Users: err = %v, want ErrUsersRequired", err)
	}
}

func TestAuthenticatorTypeAALAMRPrompts(t *testing.T) {
	t.Parallel()
	a, _, _ := newFixture(t, time.Now())
	if a.Type() != authn.FactorEmailOTP {
		t.Errorf("Type = %v, want FactorEmailOTP", a.Type())
	}
	if a.AAL() != authn.AAL2 {
		t.Errorf("AAL = %v, want AAL2", a.AAL())
	}
	if a.AMR() != "otp" {
		t.Errorf("AMR = %q, want \"otp\"", a.AMR())
	}
	got := a.Prompts()
	if len(got) != 2 || got[0] != emailotp.PromptTypeSend || got[1] != emailotp.PromptTypeVerify {
		t.Errorf("Prompts = %v, want [send, verify]", got)
	}
}

func TestBeginRequiresSubjectAndEmitsSendPrompt(t *testing.T) {
	t.Parallel()
	a, _, _ := newFixture(t, time.Now())

	if _, err := a.Begin(context.Background(), authn.BeginInput{}); !errors.Is(err, emailotp.ErrSubjectRequired) {
		t.Errorf("Begin without Subject: err = %v, want ErrSubjectRequired", err)
	}
	step, err := a.Begin(context.Background(), authn.BeginInput{Subject: "sub-1"})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != emailotp.PromptTypeSend {
		t.Fatalf("Begin step = %+v, want send prompt", step)
	}
	if _, ok := step.Prompt.Data.(interaction.EmailOTPSendPromptData); !ok {
		t.Errorf("Begin Data = %T, want EmailOTPSendPromptData", step.Prompt.Data)
	}
	if len(step.Prompt.Inputs) != 1 || step.Prompt.Inputs[0].Name != emailotp.EmailFieldName {
		t.Errorf("Begin Inputs = %+v, want single email field", step.Prompt.Inputs)
	}
}

func TestContinueSendMatchedEmailDeliversAndPersists(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	a, mailer, recStore := newFixture(t, now)

	step, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject: "sub-1",
		Submission: interaction.FormSubmission{
			Values: map[string]string{emailotp.EmailFieldName: "Alice@Example.com"},
		},
	})
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != emailotp.PromptTypeVerify {
		t.Fatalf("Continue step = %+v, want verify prompt", step)
	}
	data, ok := step.Prompt.Data.(interaction.EmailOTPVerifyPromptData)
	if !ok {
		t.Fatalf("verify Data = %T, want EmailOTPVerifyPromptData", step.Prompt.Data)
	}
	if data.MaskedEmail != "a***@e***" {
		t.Errorf("MaskedEmail = %q, want \"a***@e***\"", data.MaskedEmail)
	}
	if !data.ExpiresAt.Equal(now.Add(emailotp.DefaultCodeTTL)) {
		t.Errorf("ExpiresAt = %v, want %v", data.ExpiresAt, now.Add(emailotp.DefaultCodeTTL))
	}
	if len(step.Scratch) == 0 {
		t.Errorf("Scratch must be set on verify step")
	}
	msg, n := mailer.snapshot()
	if n != 1 {
		t.Fatalf("Mailer.Send called %d times, want 1", n)
	}
	if msg.To != "alice@example.com" {
		t.Errorf("Mailer.To = %q, want bound email", msg.To)
	}
	if len(msg.Code) != emailotp.CodeDigits {
		t.Errorf("Mailer.Code length = %d, want %d", len(msg.Code), emailotp.CodeDigits)
	}
	rec, err := recStore.Get(context.Background(), "sub-1")
	if err != nil {
		t.Fatalf("Get persisted record: %v", err)
	}
	if rec.SentAt.IsZero() {
		t.Errorf("SentAt zero on matched email")
	}
}

func TestContinueSendMismatchedEmailSkipsMailer(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	a, mailer, recStore := newFixture(t, now)

	step, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject: "sub-1",
		Submission: interaction.FormSubmission{
			Values: map[string]string{emailotp.EmailFieldName: "intruder@example.com"},
		},
	})
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != emailotp.PromptTypeVerify {
		t.Fatalf("Continue step = %+v, want verify prompt regardless of email", step)
	}
	data := step.Prompt.Data.(interaction.EmailOTPVerifyPromptData)
	if data.MaskedEmail != "a***@e***" {
		t.Errorf("MaskedEmail must reflect bound email, got %q", data.MaskedEmail)
	}
	if _, n := mailer.snapshot(); n != 0 {
		t.Errorf("Mailer.Send called %d times on mismatch, want 0", n)
	}
	rec, err := recStore.Get(context.Background(), "sub-1")
	if err != nil {
		t.Fatalf("Get persisted record: %v", err)
	}
	if !rec.SentAt.IsZero() {
		t.Errorf("SentAt non-zero on mismatched email: %v", rec.SentAt)
	}
}

func TestContinueSendMissingEmail(t *testing.T) {
	t.Parallel()
	a, _, _ := newFixture(t, time.Now())
	_, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject:    "sub-1",
		Submission: interaction.FormSubmission{Values: map[string]string{}},
	})
	if !errors.Is(err, emailotp.ErrEmailMissing) {
		t.Errorf("err = %v, want ErrEmailMissing", err)
	}
}

func TestContinueSendNoBoundEmailClaim(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	clock := &emailotp.FakeClock{T: now}
	st := inmem.New(inmem.WithClock(clock))
	users := &fakeUsers{users: map[string]*store.User{
		"sub-1": {Subject: "sub-1", Claims: map[string]any{}},
	}}
	mailer := &recordingMailer{}
	a, err := emailotp.NewAuthenticator(emailotp.Config{
		Mailer: mailer, Store: st.EmailOTPs(), Users: users, Clock: clock, SendLatencyPad: -1,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	_, err = a.Continue(context.Background(), authn.ContinueInput{
		Subject: "sub-1",
		Submission: interaction.FormSubmission{Values: map[string]string{
			emailotp.EmailFieldName: "alice@example.com",
		}},
	})
	if !errors.Is(err, emailotp.ErrEmailNotBound) {
		t.Errorf("err = %v, want ErrEmailNotBound", err)
	}
}

// driveSendStep runs the send step against the matched email and
// returns the issued code by capturing the mailer's last delivery.
func driveSendStep(t *testing.T, a *emailotp.Authenticator, mailer *recordingMailer, subject string) string {
	t.Helper()
	step, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject: subject,
		Submission: interaction.FormSubmission{Values: map[string]string{
			emailotp.EmailFieldName: "alice@example.com",
		}},
	})
	if err != nil {
		t.Fatalf("Continue (send): %v", err)
	}
	if len(step.Scratch) == 0 {
		t.Fatal("send step missing Scratch")
	}
	msg, _ := mailer.snapshot()
	if msg == nil {
		t.Fatal("mailer never invoked")
	}
	return msg.Code
}

func TestContinueVerifyCorrectCodeEmitsResult(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	a, mailer, recStore := newFixture(t, now)

	code := driveSendStep(t, a, mailer, "sub-1")
	authTime := now.Add(time.Second)
	step, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject:    "sub-1",
		AuthTime:   authTime,
		Scratch:    emailotp.ScratchVerify,
		Submission: interaction.FormSubmission{Values: map[string]string{emailotp.CodeFieldName: code}},
	})
	if err != nil {
		t.Fatalf("Continue (verify): %v", err)
	}
	if step.Result == nil || step.Result.Subject != "sub-1" {
		t.Fatalf("Result = %+v, want subject sub-1", step.Result)
	}
	if !step.Result.AuthTime.Equal(authTime) {
		t.Errorf("AuthTime = %v, want %v", step.Result.AuthTime, authTime)
	}
	// H-AUTHN-1: success now persists the record with ConsumedAt
	// stamped instead of deleting it. The single-use invariant is
	// enforced by the ConsumedAt guard on the next verify, not by
	// row absence.
	rec, gerr := recStore.Get(context.Background(), "sub-1")
	if gerr != nil {
		t.Fatalf("record dropped after success: err = %v", gerr)
	}
	if rec.ConsumedAt.IsZero() {
		t.Errorf("ConsumedAt not stamped on persisted record")
	}
}

func TestContinueVerifyWrongCodeReEmitsPromptAndIncrementsCounter(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	a, mailer, recStore := newFixture(t, now)
	_ = driveSendStep(t, a, mailer, "sub-1")

	step, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject:    "sub-1",
		Scratch:    emailotp.ScratchVerify,
		Submission: interaction.FormSubmission{Values: map[string]string{emailotp.CodeFieldName: "000000"}},
	})
	if err != nil {
		t.Fatalf("Continue (verify wrong): %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != emailotp.PromptTypeVerify {
		t.Fatalf("expected re-emitted verify prompt, got %+v", step)
	}
	rec, err := recStore.Get(context.Background(), "sub-1")
	if err != nil {
		t.Fatalf("Get record: %v", err)
	}
	if rec.FailedCount != 1 {
		t.Errorf("FailedCount = %d, want 1", rec.FailedCount)
	}
}

func TestContinueVerifyExpiredReturnsError(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	clock := &emailotp.FakeClock{T: now}
	st := inmem.New(inmem.WithClock(clock))
	users := &fakeUsers{users: map[string]*store.User{
		"sub-1": {Subject: "sub-1", Claims: map[string]any{"email": "alice@example.com"}},
	}}
	mailer := &recordingMailer{}
	a, err := emailotp.NewAuthenticator(emailotp.Config{
		Mailer: mailer, Store: st.EmailOTPs(), Users: users, Clock: clock, SendLatencyPad: -1,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	_ = driveSendStep(t, a, mailer, "sub-1")

	clock.T = now.Add(emailotp.DefaultCodeTTL + time.Second)
	_, err = a.Continue(context.Background(), authn.ContinueInput{
		Subject:    "sub-1",
		Scratch:    emailotp.ScratchVerify,
		Submission: interaction.FormSubmission{Values: map[string]string{emailotp.CodeFieldName: "000000"}},
	})
	if !errors.Is(err, emailotp.ErrExpired) {
		t.Errorf("err = %v, want ErrExpired", err)
	}
}

func TestContinueVerifyMissingCode(t *testing.T) {
	t.Parallel()
	a, _, _ := newFixture(t, time.Now())
	_, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject:    "sub-1",
		Scratch:    emailotp.ScratchVerify,
		Submission: interaction.FormSubmission{Values: map[string]string{}},
	})
	if !errors.Is(err, emailotp.ErrCodeMissing) {
		t.Errorf("err = %v, want ErrCodeMissing", err)
	}
}

func TestContinueRequiresSubject(t *testing.T) {
	t.Parallel()
	a, _, _ := newFixture(t, time.Now())
	_, err := a.Continue(context.Background(), authn.ContinueInput{})
	if !errors.Is(err, emailotp.ErrSubjectRequired) {
		t.Errorf("err = %v, want ErrSubjectRequired", err)
	}
}

// TestContinueVerifySuccessStampsConsumedAt asserts the record is
// persisted with a non-zero ConsumedAt after a successful redeem so a
// transient Delete failure cannot leave a re-redeemable record.
func TestContinueVerifySuccessStampsConsumedAt(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	a, mailer, recStore := newFixture(t, now)

	code := driveSendStep(t, a, mailer, "sub-1")
	step, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject:    "sub-1",
		Scratch:    emailotp.ScratchVerify,
		Submission: interaction.FormSubmission{Values: map[string]string{emailotp.CodeFieldName: code}},
	})
	if err != nil {
		t.Fatalf("Continue (verify): %v", err)
	}
	if step.Result == nil {
		t.Fatalf("expected Result, got %+v", step)
	}
	rec, gerr := recStore.Get(context.Background(), "sub-1")
	if gerr != nil {
		t.Fatalf("Get persisted record after success: %v", gerr)
	}
	if rec.ConsumedAt.IsZero() {
		t.Error("ConsumedAt is zero after successful verify; record left re-redeemable")
	}
}

// TestContinueVerifyReplayRejected asserts a second verify against the
// same code (e.g. from a leaked SPA log) is rejected, exercising the
// ConsumedAt guard added for H-AUTHN-1.
func TestContinueVerifyReplayRejected(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	a, mailer, _ := newFixture(t, now)

	code := driveSendStep(t, a, mailer, "sub-1")
	if _, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject:    "sub-1",
		Scratch:    emailotp.ScratchVerify,
		Submission: interaction.FormSubmission{Values: map[string]string{emailotp.CodeFieldName: code}},
	}); err != nil {
		t.Fatalf("first Continue: %v", err)
	}
	_, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject:    "sub-1",
		Scratch:    emailotp.ScratchVerify,
		Submission: interaction.FormSubmission{Values: map[string]string{emailotp.CodeFieldName: code}},
	})
	if !errors.Is(err, emailotp.ErrExpired) {
		t.Errorf("replay err = %v, want ErrExpired", err)
	}
}

// TestVerifyConsumedRecordRejectedDirect exercises the verifier-level
// ConsumedAt guard (the authenticator wraps it as ErrExpired).
func TestVerifyConsumedRecordRejectedDirect(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	v := &emailotp.Verifier{Clock: &emailotp.FakeClock{T: now}}
	rec := &store.EmailOTPRecord{
		Subject:    "sub-1",
		ExpiresAt:  now.Add(5 * time.Minute),
		ConsumedAt: now.Add(-time.Minute),
	}
	res, err := v.Verify(context.Background(), rec, "000000")
	if !errors.Is(err, emailotp.ErrConsumed) {
		t.Errorf("err = %v, want ErrConsumed", err)
	}
	if res == nil || res.Outcome != emailotp.OutcomeConsumed {
		t.Errorf("Outcome = %+v, want OutcomeConsumed", res)
	}
}
