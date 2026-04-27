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
