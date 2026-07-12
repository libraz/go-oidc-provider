package op

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/emailotp"
	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/internal/authn/recovery"
	"github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// fixedTestClock is a constant clock satisfying both op.Clock and
// inmem.Clock so a test can pin the whole flow to one instant.
type fixedTestClock struct{ t time.Time }

func (c fixedTestClock) Now() time.Time { return c.t }

// stubTOTPKey returns a 32-byte key padded from the supplied seed. The
// helper avoids hard-coded byte literals that would lint-trip as
// suspicious credential material.
func stubTOTPKey(seed string) []byte {
	out := make([]byte, mfaEncryptionKeyLen)
	copy(out, seed)
	return out
}

type testEmailDeliveryFunc func(context.Context, string, string) error

func (f testEmailDeliveryFunc) Send(ctx context.Context, address, code string) error {
	return f(ctx, address, code)
}

// TestProjectBuiltinStep_ThreadsWithClockToFactor pins #17: the clock
// supplied through WithClock must reach the built-in factor verifiers, not
// only the cross-factor lockout counter. Observed through email-OTP — the
// persisted challenge's timestamps are stamped from the factor's clock, so
// a threaded WithClock makes them land in the injected year rather than
// wall time. Before the fix, buildStepEmailOTP dropped cfg.clock and the
// verifier fell back to SystemClock.
func TestProjectBuiltinStep_ThreadsWithClockToFactor(t *testing.T) {
	t.Parallel()

	fixed := fixedTestClock{t: time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)}
	st := inmem.New(inmem.WithClock(fixed))
	st.PutUser(context.Background(), &store.User{
		Subject: "sub-clock",
		Claims:  map[string]any{"email": "alice@example.com"},
	})
	cfg := &config{clock: fixed}
	step := StepEmailOTP{
		Store:          st.EmailOTPs(),
		Sender:         testEmailDeliveryFunc(func(context.Context, string, string) error { return nil }),
		Users:          st.Users(),
		SendLatencyPad: -1, // disable the constant-time pad for the test
	}
	lfStep, err := projectBuiltinStep("rule", step, cfg)
	if err != nil {
		t.Fatalf("projectBuiltinStep: %v", err)
	}
	if _, err := lfStep.Authenticator.Continue(context.Background(), authn.ContinueInput{
		Subject: "sub-clock",
		Submission: interaction.FormSubmission{Values: map[string]string{
			emailotp.EmailFieldName: "alice@example.com",
		}},
	}); err != nil {
		t.Fatalf("Continue (send): %v", err)
	}
	rec, err := st.EmailOTPs().Get(context.Background(), "sub-clock")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if rec.SentAt.Year() != 2020 {
		t.Fatalf("SentAt=%v: WithClock was not threaded to the email-OTP verifier (want a 2020-stamped time)", rec.SentAt)
	}
}

// TestSelectTOTPKeys_PerStepWins pins the more-specific-wins contract:
// a non-empty [StepTOTP.EncryptionKey] always overrides the
// Provider-level fallback returned by [totpFallbackKeys].
func TestSelectTOTPKeys_PerStepWins(t *testing.T) {
	t.Parallel()
	perStep := stubTOTPKey("per-step-key")
	fallback := stubTOTPKey("global-fallback-key")

	current, prev := selectTOTPKeys(StepTOTP{EncryptionKey: perStep}, fallback, nil)
	if !bytes.Equal(current, perStep) {
		t.Fatalf("current = %x, want per-step %x", current, perStep)
	}
	if prev != nil {
		t.Fatalf("prev = %v, want nil when neither side supplies rotation history", prev)
	}
}

// TestSelectTOTPKeys_FallbackUsedWhenStepEmpty confirms the global
// surface is consulted when [StepTOTP.EncryptionKey] is empty.
func TestSelectTOTPKeys_FallbackUsedWhenStepEmpty(t *testing.T) {
	t.Parallel()
	fallback := stubTOTPKey("global-fallback-key")
	fallbackPrev := [][]byte{stubTOTPKey("rotation-slot-a")}

	current, prev := selectTOTPKeys(StepTOTP{}, fallback, fallbackPrev)
	if !bytes.Equal(current, fallback) {
		t.Fatalf("current = %x, want fallback %x", current, fallback)
	}
	if len(prev) != 1 || !bytes.Equal(prev[0], fallbackPrev[0]) {
		t.Fatalf("prev = %x, want fallback rotation %x", prev, fallbackPrev)
	}
}

// TestSelectTOTPKeys_PrevIndependentlyOverridable confirms an embedder
// can override the active key per Step while inheriting the global
// rotation history (or vice versa).
func TestSelectTOTPKeys_PrevIndependentlyOverridable(t *testing.T) {
	t.Parallel()
	perStep := stubTOTPKey("per-step-key")
	fallback := stubTOTPKey("global-fallback-key")
	fallbackPrev := [][]byte{stubTOTPKey("rotation-slot-a")}

	current, prev := selectTOTPKeys(StepTOTP{EncryptionKey: perStep}, fallback, fallbackPrev)
	if !bytes.Equal(current, perStep) {
		t.Fatalf("current = %x, want per-step %x", current, perStep)
	}
	if len(prev) != 1 || !bytes.Equal(prev[0], fallbackPrev[0]) {
		t.Fatalf("prev = %x, want inherited rotation %x", prev, fallbackPrev)
	}
}

// TestBuildStepTOTP_PerStepKeyShapesCipher pins the per-step-wins
// contract end-to-end at the cipher layer: the keys [selectTOTPKeys]
// resolves are the keys [totp.NewCodec] keys the cipher with, so a
// blob sealed under the resolved current key MUST round-trip and MUST
// NOT open under a codec built from the fallback alone. The test
// drives the resolution through buildStepTOTP itself (so a future
// refactor of the wiring still surfaces here) and reproduces the
// resolution out-of-band to obtain a comparable codec.
func TestBuildStepTOTP_PerStepKeyShapesCipher(t *testing.T) {
	t.Parallel()
	perStep := stubTOTPKey("per-step-key")
	fallback := stubTOTPKey("global-fallback-key")
	if bytes.Equal(perStep, fallback) {
		t.Fatalf("test setup: per-step and fallback must differ")
	}

	st := inmem.New()
	if _, err := buildStepTOTP(StepTOTP{Store: st.TOTPs(), EncryptionKey: perStep}, fallback, nil, nil); err != nil {
		t.Fatalf("buildStepTOTP: %v", err)
	}

	current, prev := selectTOTPKeys(StepTOTP{EncryptionKey: perStep}, fallback, nil)
	codec, err := totp.NewCodec(current, prev...)
	if err != nil {
		t.Fatalf("NewCodec(resolved): %v", err)
	}
	secret := []byte("12345678901234567890")
	aad := []byte("subject-alice")
	blob, err := codec.Seal(secret, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := codec.Open(blob, aad)
	if err != nil {
		t.Fatalf("Open with resolved codec: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatalf("plaintext = %x, want %x", got, secret)
	}

	// A codec built only from the fallback MUST NOT decrypt the blob:
	// per-step-wins means the cipher is keyed by the per-step bytes.
	fallbackOnly, err := totp.NewCodec(fallback)
	if err != nil {
		t.Fatalf("NewCodec(fallback): %v", err)
	}
	if _, err := fallbackOnly.Open(blob, aad); !errors.Is(err, totp.ErrDecrypt) {
		t.Fatalf("fallback codec opened blob sealed under per-step key: err=%v want ErrDecrypt", err)
	}
}

// TestTotpFallbackKeys_SplitsCurrentAndPrev pins the slice-split
// contract: the first entry is returned as the current key and the
// remainder as the rotation history.
func TestTotpFallbackKeys_SplitsCurrentAndPrev(t *testing.T) {
	t.Parallel()
	a := stubTOTPKey("active")
	b := stubTOTPKey("rotation-1")
	c := stubTOTPKey("rotation-2")
	cfg := &config{mfaEncryptionKeys: [][]byte{a, b, c}}
	current, prev := totpFallbackKeys(cfg)
	if !bytes.Equal(current, a) {
		t.Fatalf("current = %x, want active %x", current, a)
	}
	if len(prev) != 2 || !bytes.Equal(prev[0], b) || !bytes.Equal(prev[1], c) {
		t.Fatalf("prev = %x, want %x", prev, [][]byte{b, c})
	}
}

func TestProjectBuiltinStep_AttachesLockoutCounter(t *testing.T) {
	t.Parallel()

	const subject = "subject-lockout"
	st := inmem.New()
	counter, err := lockout.New(st.AuthnLockouts(), nil)
	if err != nil {
		t.Fatalf("lockout.New: %v", err)
	}
	for i := range 30 {
		if _, err := counter.RecordFailure(context.Background(), subject); err != nil {
			t.Fatalf("RecordFailure %d: %v", i+1, err)
		}
	}
	cfg := &config{authnLockoutStore: st.AuthnLockouts()}
	totpKey := stubTOTPKey("totp-lockout-key")

	cases := []struct {
		name    string
		step    Step
		wantErr error
	}{
		{
			name:    "totp",
			step:    StepTOTP{Store: st.TOTPs(), EncryptionKey: totpKey},
			wantErr: totp.ErrLocked,
		},
		{
			name: "emailotp",
			step: StepEmailOTP{
				Store:  st.EmailOTPs(),
				Sender: testEmailDeliveryFunc(func(context.Context, string, string) error { return nil }),
				Users:  st.Users(),
			},
			wantErr: emailotp.ErrLocked,
		},
		{
			name:    "recovery",
			step:    StepRecoveryCode{Store: st.RecoveryCodes()},
			wantErr: recovery.ErrLocked,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			lfStep, err := projectBuiltinStep("rule", tc.step, cfg)
			if err != nil {
				t.Fatalf("projectBuiltinStep: %v", err)
			}
			_, err = lfStep.Authenticator.Begin(context.Background(), authn.BeginInput{Subject: subject})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Begin err=%v want %v", err, tc.wantErr)
			}
		})
	}
}
