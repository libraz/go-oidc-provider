package lockout_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/internal/authn/recovery"
	"github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// The two PromptData types that carry an AttemptsRemaining field share
// one doc comment defining it as the failed submissions left before the
// factor locks. A field defined once has to be produced once: a driver
// renders both prompts through the same template, and a number that means
// "guesses left" on one screen and "recovery codes you still hold" on the
// other is a wire contract with two meanings and a disclosure on top.
//
// The test drives both factors against one subject and one shared
// counter, so the comparison is between two live prompts rather than
// between each adapter and a hard-coded constant.
func TestPromptAttemptsRemainingAgreesAcrossFactors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	const subject = "user-alice"
	clock := &fakeClock{t: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)}
	st := inmem.New()

	counter, err := lockout.New(st.AuthnLockouts(), clock)
	if err != nil {
		t.Fatalf("lockout.New: %v", err)
	}
	totpAuth := newTOTPFactor(t, st, clock, subject, counter)
	recoveryAuth := newRecoveryFactor(t, st, clock, subject, counter)

	// A subject with a fresh batch of ten codes and nothing spent
	// against the shared counter.
	totpAttempts := promptAttempts(t, beginPrompt(ctx, t, totpAuth, subject, clock.Now()))
	recoveryAttempts := promptAttempts(t, beginPrompt(ctx, t, recoveryAuth, subject, clock.Now()))
	if recoveryAttempts != totpAttempts {
		t.Fatalf("recovery AttemptsRemaining = %d, TOTP AttemptsRemaining = %d; one field, one meaning",
			recoveryAttempts, totpAttempts)
	}
	if recoveryAttempts == 10 {
		t.Errorf("AttemptsRemaining = 10, which is the number of unconsumed recovery codes rather than the "+
			"failure budget both prompts promise (%d)", totpAttempts)
	}
}

// newTOTPFactor seeds a confirmed TOTP enrolment for subject and returns
// the adapter wired to the shared counter.
func newTOTPFactor(
	t *testing.T,
	st *inmem.Store,
	clock *fakeClock,
	subject string,
	counter *lockout.Counter,
) *totp.Authenticator {
	t.Helper()

	codec, err := totp.NewCodec(make([]byte, 32))
	if err != nil {
		t.Fatalf("totp.NewCodec: %v", err)
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatalf("totp.GenerateSecret: %v", err)
	}
	blob, err := codec.Seal(secret, []byte(subject))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if err := st.TOTPs().Put(context.Background(), &store.TOTPRecord{
		Subject:          subject,
		SecretCiphertext: blob,
		ConfirmedAt:      clock.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("TOTPs.Put: %v", err)
	}
	auth, err := totp.NewAuthenticator(&totp.Verifier{Clock: clock, Codec: codec}, st.TOTPs())
	if err != nil {
		t.Fatalf("totp.NewAuthenticator: %v", err)
	}
	return auth.WithLockout(counter)
}

// newRecoveryFactor generates a batch for subject and returns the adapter
// wired to the shared counter.
func newRecoveryFactor(
	t *testing.T,
	st *inmem.Store,
	clock *fakeClock,
	subject string,
	counter *lockout.Counter,
) *recovery.Authenticator {
	t.Helper()

	verifier := &recovery.Verifier{Clock: clock}
	res, err := verifier.Generate(context.Background(), subject)
	if err != nil {
		t.Fatalf("recovery.Generate: %v", err)
	}
	if len(res.PlaintextCodes) != 10 {
		t.Fatalf("generated %d recovery codes, want 10: the test compares the budget against the slot count",
			len(res.PlaintextCodes))
	}
	if err := st.RecoveryCodes().Put(context.Background(), res.Batch); err != nil {
		t.Fatalf("RecoveryCodes.Put: %v", err)
	}
	auth, err := recovery.NewAuthenticator(verifier, st.RecoveryCodes())
	if err != nil {
		t.Fatalf("recovery.NewAuthenticator: %v", err)
	}
	return auth.WithLockout(counter)
}

// beginPrompt runs the factor's Begin and returns the prompt it emitted.
func beginPrompt(ctx context.Context, t *testing.T, auth authn.Authenticator, subject string, now time.Time) *interaction.Prompt {
	t.Helper()

	step, err := auth.Begin(ctx, authn.BeginInput{Subject: subject, AuthTime: now})
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if step.Prompt == nil {
		t.Fatalf("Begin returned %+v, want a Prompt", step)
	}
	return step.Prompt
}

// promptAttempts reads AttemptsRemaining off whichever of the two
// PromptData types the prompt carries.
func promptAttempts(t *testing.T, prompt *interaction.Prompt) int {
	t.Helper()

	switch data := prompt.Data.(type) {
	case interaction.TOTPPromptData:
		return data.AttemptsRemaining
	case interaction.RecoveryCodePromptData:
		return data.AttemptsRemaining
	default:
		t.Fatalf("Prompt.Data type = %T, want one of the AttemptsRemaining-carrying types", prompt.Data)
		return 0
	}
}
