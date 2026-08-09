package op_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type stubUsers struct{ u *store.User }

func (s stubUsers) FindBySubject(_ context.Context, sub string) (*store.User, error) {
	if s.u != nil && s.u.Subject == sub {
		return s.u, nil
	}
	return nil, store.ErrNotFound
}

func TestNewEmailOTPAuthenticator_DeliversThroughPublicMailer(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	st := inmem.New(inmem.WithClock(fixedClock{t: now}))
	users := stubUsers{u: &store.User{
		Subject: "sub-1",
		Claims:  map[string]any{"email": "alice@example.com"},
	}}

	delivered := make(chan op.EmailOTPMessage, 1)
	auth, err := op.NewEmailOTPAuthenticator(op.EmailOTPConfig{
		Mailer: op.MailerFunc(func(_ context.Context, msg op.EmailOTPMessage) error {
			delivered <- msg
			return nil
		}),
		Store: st.EmailOTPs(),
		Users: users,
		Clock: fixedClock{t: now},
	})
	if err != nil {
		t.Fatalf("NewEmailOTPAuthenticator: %v", err)
	}
	if auth.Type() != op.FactorEmailOTP {
		t.Fatalf("Type = %v, want FactorEmailOTP", auth.Type())
	}

	step, err := auth.Continue(context.Background(), op.ContinueInput{
		Subject: "sub-1",
		Submission: interaction.FormSubmission{
			Values: map[string]string{"email": "alice@example.com"},
		},
	})
	if err != nil {
		t.Fatalf("Continue: %v", err)
	}
	if step.Prompt == nil || step.Prompt.Type != "auth.email_otp.verify" {
		t.Fatalf("step = %+v, want verify prompt", step)
	}
	select {
	case msg := <-delivered:
		if msg.To != "alice@example.com" {
			t.Errorf("Mailer.To = %q, want bound email", msg.To)
		}
		if len(msg.Code) != 6 {
			t.Errorf("Mailer.Code length = %d, want 6", len(msg.Code))
		}
		if !msg.ExpiresAt.Equal(now.Add(op.DefaultEmailOTPCodeTTL)) {
			t.Errorf("ExpiresAt = %v, want %v", msg.ExpiresAt, now.Add(op.DefaultEmailOTPCodeTTL))
		}
		if msg.Subject != "sub-1" {
			t.Errorf("Subject audit-binding = %q, want sub-1", msg.Subject)
		}
	default:
		t.Fatal("mailer not invoked")
	}
}

func TestNewEmailOTPAuthenticator_RejectsMissingDeps(t *testing.T) {
	t.Parallel()
	users := stubUsers{}
	st := inmem.New().EmailOTPs()
	mailer := op.MailerFunc(func(_ context.Context, _ op.EmailOTPMessage) error { return nil })

	cases := []struct {
		name string
		cfg  op.EmailOTPConfig
	}{
		{"missing mailer", op.EmailOTPConfig{Store: st, Users: users}},
		{"missing store", op.EmailOTPConfig{Mailer: mailer, Users: users}},
		{"missing users", op.EmailOTPConfig{Mailer: mailer, Store: st}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := op.NewEmailOTPAuthenticator(tc.cfg); err == nil {
				t.Fatalf("%s: expected error, got nil", tc.name)
			}
		})
	}
}

func TestNewEmailOTPAuthenticator_DefaultClockAndTTL(t *testing.T) {
	t.Parallel()
	st := inmem.New()
	users := stubUsers{u: &store.User{
		Subject: "sub-1", Claims: map[string]any{"email": "alice@example.com"},
	}}
	mailer := op.MailerFunc(func(_ context.Context, _ op.EmailOTPMessage) error { return nil })

	auth, err := op.NewEmailOTPAuthenticator(op.EmailOTPConfig{
		Mailer: mailer, Store: st.EmailOTPs(), Users: users,
		// Clock and CodeTTL deliberately zero so we exercise the
		// fallback path.
	})
	if err != nil {
		t.Fatalf("NewEmailOTPAuthenticator (defaults): %v", err)
	}
	if auth == nil {
		t.Fatal("expected non-nil authenticator")
	}
}

// TestNewEmailOTPAuthenticator_SharesTheCrossFactorLockout drives the
// shared per-subject counter through the public constructor. The
// directly constructed authenticator has to land on the same budget the
// LoginFlow path attaches, or an attacker who has burned their TOTP
// allowance can pivot to email OTP and start over.
//
// Both halves read the store rather than the authenticator: a lock
// another factor stamped must stop this one, and a guess this one
// refuses must be visible to every other factor.
func TestNewEmailOTPAuthenticator_SharesTheCrossFactorLockout(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	st := inmem.New(inmem.WithClock(fixedClock{t: now}))
	users := stubUsers{u: &store.User{
		Subject: "sub-locked",
		Claims:  map[string]any{"email": "alice@example.com"},
	}}
	mailer := op.MailerFunc(func(_ context.Context, _ op.EmailOTPMessage) error { return nil })

	newAuth := func(t *testing.T, lockouts store.AuthnLockoutStore) op.Authenticator {
		t.Helper()
		auth, err := op.NewEmailOTPAuthenticator(op.EmailOTPConfig{
			Mailer:       mailer,
			Store:        st.EmailOTPs(),
			Users:        users,
			Clock:        fixedClock{t: now},
			LockoutStore: lockouts,
		})
		if err != nil {
			t.Fatalf("NewEmailOTPAuthenticator: %v", err)
		}
		return auth
	}

	// Some other factor has already locked this subject out.
	swapped, err := st.AuthnLockouts().CompareAndSwap(ctx, 0, &store.AuthnLockoutRecord{
		Subject:        "sub-locked",
		FailedCount:    30,
		FirstFailureAt: now.Add(-2 * time.Hour),
		LockedUntil:    now.Add(time.Hour),
	})
	if err != nil || !swapped {
		t.Fatalf("seed lockout record: swapped=%v err=%v", swapped, err)
	}

	if _, err := newAuth(t, st.AuthnLockouts()).Begin(ctx, op.BeginInput{Subject: "sub-locked"}); err == nil {
		t.Error("Begin succeeded for a subject another factor locked out; the counter is not wired")
	}

	// Without the store the factor keeps its own budget only, which is
	// what makes the assertion above about wiring rather than about the
	// subject.
	step, err := newAuth(t, nil).Begin(ctx, op.BeginInput{Subject: "sub-locked"})
	if err != nil {
		t.Fatalf("Begin without a lockout store: %v", err)
	}
	if step.Prompt == nil {
		t.Error("Begin without a lockout store returned no prompt")
	}
}

// TestNewEmailOTPAuthenticator_RecordsFailuresOnTheSharedCounter is the
// other direction of the same wiring: a wrong code submitted to a
// directly constructed authenticator has to advance the counter every
// other factor reads, not just the per-challenge counter.
func TestNewEmailOTPAuthenticator_RecordsFailuresOnTheSharedCounter(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	st := inmem.New(inmem.WithClock(fixedClock{t: now}))
	users := stubUsers{u: &store.User{
		Subject: "sub-guess",
		Claims:  map[string]any{"email": "alice@example.com"},
	}}

	delivered := make(chan op.EmailOTPMessage, 1)
	auth, err := op.NewEmailOTPAuthenticator(op.EmailOTPConfig{
		Mailer: op.MailerFunc(func(_ context.Context, msg op.EmailOTPMessage) error {
			delivered <- msg
			return nil
		}),
		Store:        st.EmailOTPs(),
		Users:        users,
		Clock:        fixedClock{t: now},
		LockoutStore: st.AuthnLockouts(),
	})
	if err != nil {
		t.Fatalf("NewEmailOTPAuthenticator: %v", err)
	}

	sent, err := auth.Continue(ctx, op.ContinueInput{
		Subject: "sub-guess",
		Submission: interaction.FormSubmission{
			Values: map[string]string{"email": "alice@example.com"},
		},
	})
	if err != nil {
		t.Fatalf("send step: %v", err)
	}
	issued := <-delivered

	// A code that is definitely not the one delivered.
	wrong := "000000"
	if issued.Code == wrong {
		wrong = "111111"
	}
	if _, err := auth.Continue(ctx, op.ContinueInput{
		Subject: "sub-guess",
		Scratch: sent.Scratch,
		Submission: interaction.FormSubmission{
			Values: map[string]string{"code": wrong},
		},
	}); err == nil {
		t.Fatal("verify accepted a wrong code")
	}

	rec, err := st.AuthnLockouts().Get(ctx, "sub-guess")
	if err != nil {
		t.Fatalf("read the shared counter: %v", err)
	}
	if rec.FailedCount != 1 {
		t.Errorf("shared FailedCount = %d, want 1; the wrong guess did not reach the cross-factor counter", rec.FailedCount)
	}
}

// TestNewEmailOTPAuthenticator_RejectsTypedNilLockoutStore pins the
// refusal that keeps the option from failing open: a typed-nil store is
// a wiring mistake, and accepting it would leave the factor silently
// outside the shared budget.
func TestNewEmailOTPAuthenticator_RejectsTypedNilLockoutStore(t *testing.T) {
	t.Parallel()

	var typedNil *nilLockoutStore
	_, err := op.NewEmailOTPAuthenticator(op.EmailOTPConfig{
		Mailer:       op.MailerFunc(func(_ context.Context, _ op.EmailOTPMessage) error { return nil }),
		Store:        inmem.New().EmailOTPs(),
		Users:        stubUsers{},
		LockoutStore: typedNil,
	})
	if err == nil {
		t.Fatal("NewEmailOTPAuthenticator accepted a typed-nil LockoutStore")
	}
}

// nilLockoutStore exists only so a test can build a typed-nil
// [store.AuthnLockoutStore]; its methods are never called.
type nilLockoutStore struct{}

func (*nilLockoutStore) Get(context.Context, string) (*store.AuthnLockoutRecord, error) {
	return nil, store.ErrNotFound
}

func (*nilLockoutStore) CompareAndSwap(context.Context, uint64, *store.AuthnLockoutRecord) (bool, error) {
	return false, nil
}

func TestMailerFunc_ImplementsMailer(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("rejected")
	m := op.MailerFunc(func(_ context.Context, _ op.EmailOTPMessage) error { return sentinel })
	var mailer op.Mailer = m
	err := mailer.Send(context.Background(), op.EmailOTPMessage{To: "x@y"})
	if !errors.Is(err, sentinel) {
		t.Fatalf("Send err = %v, want sentinel", err)
	}
}
