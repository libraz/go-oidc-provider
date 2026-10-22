package authn_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/emailotp"
	"github.com/libraz/go-oidc-provider/internal/authn/recovery"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// otpMailbox captures the code the email-OTP factor delivers.
type otpMailbox struct {
	mu   sync.Mutex
	code string
}

func (m *otpMailbox) Send(_ context.Context, msg emailotp.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.code = msg.Code
	return nil
}

func (m *otpMailbox) delivered() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.code
}

// TestSingleUseSecretNamespacesAreDisjoint enrols one subject for both
// email OTP and recovery codes on a shared store and cross-submits every
// secret the OP mints: a recovery code to the email-OTP verify step, an
// email-OTP code to the recovery step, and a live interaction StateRef to
// both. None may authenticate, and none may consume the secret it
// impersonates, so each factor's genuine code still redeems exactly once.
//
// Tracks: CVE-2026-110862 (Better Auth — OAuth state values were accepted as magic-link tokens because both lived in one verification table)
func TestSingleUseSecretNamespacesAreDisjoint(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const subject = "user-namespaces"
	now := fakeNow()
	clock := timex.ClockFunc(func() time.Time { return now })
	st := inmem.New(inmem.WithClock(clock))
	st.PutUser(ctx, &store.User{Subject: subject, Claims: map[string]any{"email": "alice@example.com"}})

	mailbox := &otpMailbox{}
	emailAuth, err := emailotp.NewAuthenticator(emailotp.Config{
		Mailer:         mailbox,
		Store:          st.EmailOTPs(),
		Users:          st.Users(),
		Clock:          clock,
		SendLatencyPad: -1,
	})
	if err != nil {
		t.Fatalf("emailotp.NewAuthenticator: %v", err)
	}
	verifier := &recovery.Verifier{Clock: clock}
	batch, err := verifier.Replace(ctx, st.RecoveryCodes(), subject)
	if err != nil {
		t.Fatalf("recovery Replace: %v", err)
	}
	recoveryAuth, err := recovery.NewAuthenticator(verifier, st.RecoveryCodes())
	if err != nil {
		t.Fatalf("recovery.NewAuthenticator: %v", err)
	}
	recoveryCode := batch.PlaintextCodes[0]

	sent, err := emailAuth.Continue(ctx, authn.ContinueInput{
		Subject:    subject,
		AuthTime:   now,
		Submission: interaction.FormSubmission{Values: map[string]string{emailotp.EmailFieldName: "alice@example.com"}},
	})
	if err != nil {
		t.Fatalf("email-OTP send: %v", err)
	}
	emailCode := mailbox.delivered()
	if emailCode == "" {
		t.Fatal("no email-OTP code delivered")
	}
	verifyScratch := sent.Scratch

	liveStateRef, err := newSigner(t).Issue("uid-test", "auth.0", 0, now.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("StateRef Issue: %v", err)
	}

	toEmailOTP := func(code string) (interaction.Step, error) {
		return emailAuth.Continue(ctx, authn.ContinueInput{
			Subject:    subject,
			AuthTime:   now,
			Scratch:    verifyScratch,
			Submission: interaction.FormSubmission{Values: map[string]string{emailotp.CodeFieldName: code}},
		})
	}
	toRecovery := func(code string) (interaction.Step, error) {
		return recoveryAuth.Continue(ctx, authn.ContinueInput{
			Subject:    subject,
			AuthTime:   now,
			Submission: interaction.FormSubmission{Values: map[string]string{recovery.CodeFieldName: code}},
		})
	}

	crossed := []struct {
		name   string
		submit func(string) (interaction.Step, error)
		code   string
	}{
		{"recovery code at email-OTP verify", toEmailOTP, recoveryCode},
		{"StateRef at email-OTP verify", toEmailOTP, liveStateRef},
		{"email-OTP code at recovery", toRecovery, emailCode},
		{"StateRef at recovery", toRecovery, liveStateRef},
	}
	for _, c := range crossed {
		step, err := c.submit(c.code)
		if !errors.Is(err, authn.ErrFactorRetry) {
			t.Errorf("%s: err = %v, want a soft credential rejection", c.name, err)
		}
		if step.Result != nil {
			t.Errorf("%s: authenticated as %q", c.name, step.Result.Subject)
		}
	}

	// The impersonated secrets were not spent by the failed attempts.
	if step, err := toEmailOTP(emailCode); err != nil || step.Result == nil {
		t.Fatalf("genuine email-OTP code after cross-submissions: err=%v step=%+v", err, step)
	}
	if step, err := toRecovery(recoveryCode); err != nil || step.Result == nil {
		t.Fatalf("genuine recovery code after cross-submissions: err=%v step=%+v", err, step)
	}

	// Both are now spent: neither redeems again, through either factor.
	for name, submit := range map[string]func(string) (interaction.Step, error){
		"email-OTP": toEmailOTP, "recovery": toRecovery,
	} {
		for what, code := range map[string]string{"email-OTP code": emailCode, "recovery code": recoveryCode} {
			if step, _ := submit(code); step.Result != nil {
				t.Errorf("spent %s redeemed again at %s", what, name)
			}
		}
	}
}
