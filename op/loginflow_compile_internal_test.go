package op

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/emailotp"
	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/internal/authn/password"
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

// TestProjectBuiltinStep_ThreadsWithClockToFactor pins that the clock
// supplied through WithClock reaches the built-in factor verifiers, not
// only the cross-factor lockout counter. Observed through email-OTP — the
// persisted challenge's timestamps are stamped from the factor's clock, so
// a threaded WithClock makes them land in the injected year rather than
// wall time. Drop the clock in buildStepEmailOTP and the verifier falls
// back to SystemClock, which no test can pin.
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

// movableTestClock is a clock a test advances by hand. The mutex guards
// the in-memory store's own reads of it.
type movableTestClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *movableTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *movableTestClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// emailOTPHarness compiles a StepEmailOTP for subject and captures the
// codes its sender delivers.
func emailOTPHarness(t *testing.T, cfg *config, st *inmem.Store, subject string) (authn.Authenticator, <-chan string) { //nolint:ireturn // the compiled step is only reachable as the orchestrator interface.
	t.Helper()
	st.PutUser(context.Background(), &store.User{
		Subject: subject,
		Claims:  map[string]any{"email": "alice@example.com"},
	})
	codes := make(chan string, 4)
	lfStep, err := projectBuiltinStep("rule", StepEmailOTP{
		Store: st.EmailOTPs(),
		Sender: testEmailDeliveryFunc(func(_ context.Context, _, code string) error {
			codes <- code
			return nil
		}),
		Users:          st.Users(),
		SendLatencyPad: -1,
	}, cfg)
	if err != nil {
		t.Fatalf("projectBuiltinStep: %v", err)
	}
	return lfStep.Authenticator, codes
}

func emailOTPSend(t *testing.T, auth authn.Authenticator, subject string) authn.ContinueInput {
	t.Helper()
	sent, err := auth.Continue(context.Background(), authn.ContinueInput{
		Subject: subject,
		Submission: interaction.FormSubmission{Values: map[string]string{
			emailotp.EmailFieldName: "alice@example.com",
		}},
	})
	if err != nil {
		t.Fatalf("send step: %v", err)
	}
	return authn.ContinueInput{Subject: subject, Scratch: sent.Scratch}
}

// TestStepEmailOTP_RecordsFailuresOnTheSharedCounter pins that a wrong
// code submitted to the compiled step advances the per-subject counter
// every other factor reads, not only the per-challenge counter.
func TestStepEmailOTP_RecordsFailuresOnTheSharedCounter(t *testing.T) {
	t.Parallel()

	const subject = "sub-guess"
	st := inmem.New()
	auth, codes := emailOTPHarness(t, &config{authnLockoutStore: st.AuthnLockouts()}, st, subject)
	in := emailOTPSend(t, auth, subject)

	wrong := "000000"
	if issued := <-codes; issued == wrong {
		wrong = "111111"
	}
	in.Submission = interaction.FormSubmission{Values: map[string]string{emailotp.CodeFieldName: wrong}}
	if _, err := auth.Continue(context.Background(), in); err == nil {
		t.Fatal("verify accepted a wrong code")
	}
	rec, err := st.AuthnLockouts().Get(context.Background(), subject)
	if err != nil {
		t.Fatalf("read the shared counter: %v", err)
	}
	if rec.FailedCount != 1 {
		t.Errorf("shared FailedCount = %d, want 1", rec.FailedCount)
	}
}

// TestStepEmailOTP_ConfiguredClockGatesCodeExpiry pins that the clock
// handed to the compiled step decides when a code expires: the same code
// verifies inside the window and is refused once the clock moves past it.
func TestStepEmailOTP_ConfiguredClockGatesCodeExpiry(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name    string
		advance time.Duration
		wantOK  bool
	}{
		{"inside the window", emailotp.DefaultCodeTTL - time.Minute, true},
		{"past the window", emailotp.DefaultCodeTTL + time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			clock := &movableTestClock{t: start}
			st := inmem.New(inmem.WithClock(clock))
			auth, codes := emailOTPHarness(t, &config{clock: clock}, st, "sub-expiry")
			in := emailOTPSend(t, auth, "sub-expiry")
			code := <-codes

			clock.advance(tc.advance)
			in.Submission = interaction.FormSubmission{Values: map[string]string{emailotp.CodeFieldName: code}}
			step, err := auth.Continue(context.Background(), in)
			if tc.wantOK {
				if err != nil || step.Result == nil {
					t.Fatalf("verify inside the window: step=%+v err=%v", step, err)
				}
				return
			}
			if err == nil || step.Result != nil {
				t.Fatalf("verify accepted an expired code: step=%+v err=%v", step, err)
			}
		})
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

// TestProjectBuiltinStep_AttachesLockoutCounter pins that every built-in
// credential step compiled from a LoginFlow shares one per-subject
// lockout counter, so no factor path gets a budget of its own.
//
// Tracks: CVE-2026-58271 (sync-in — TOTP brute force through an endpoint
// that lacked the login path's attempt limit), CVE-2026-105835 (PLANKA —
// wrong TOTP codes were not rate limited), CVE-2026-111356 (MacCMS — a
// six-digit recovery code had no attempt limit).
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

	const (
		username = "lockout-user"
		secret   = "correct horse battery staple"
	)
	hash, err := HashPassword(secret)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	st.PutUserWithPassword(context.Background(), &store.User{Subject: subject}, username, hash)

	cases := []struct {
		name    string
		step    Step
		wantErr error
		// cont, when set, drives Continue instead of Begin: the password
		// step guards at the point the credential is submitted.
		cont *authn.ContinueInput
	}{
		{
			name:    "password",
			step:    PrimaryPassword{Store: st.UserPasswords()},
			wantErr: password.ErrInvalidCredentials,
			cont: &authn.ContinueInput{Submission: interaction.FormSubmission{Values: map[string]string{
				password.UsernameFieldName: username,
				password.PasswordFieldName: secret,
			}}},
		},
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
			if tc.cont != nil {
				_, err = lfStep.Authenticator.Continue(context.Background(), *tc.cont)
			} else {
				_, err = lfStep.Authenticator.Begin(context.Background(), authn.BeginInput{Subject: subject})
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err=%v want %v", err, tc.wantErr)
			}
		})
	}
}

// noLockoutsStore is a store whose method set has no AuthnLockouts
// accessor, like a user-supplied or redis-style store.
type noLockoutsStore struct{ store.Store }

// nilLockoutsStore exposes the accessor but has no lockout backend, the
// way a composite whose Users side lacks one does.
type nilLockoutsStore struct{ store.Store }

func (nilLockoutsStore) AuthnLockouts() store.AuthnLockoutStore { return nil }

// TestResolveAuthnLockoutStore pins the precedence: an explicit
// WithAuthnLockoutStore, then the WithStore accessor, then nothing.
func TestResolveAuthnLockoutStore(t *testing.T) {
	t.Parallel()

	auto := inmem.New()
	explicit := inmem.New().AuthnLockouts()

	cases := []struct {
		name string
		cfg  *config
		want store.AuthnLockoutStore
	}{
		{name: "nil config", cfg: nil, want: nil},
		{name: "no store at all", cfg: &config{}, want: nil},
		{name: "store without accessor", cfg: &config{store: noLockoutsStore{Store: auto}}, want: nil},
		{name: "accessor returns nil", cfg: &config{store: nilLockoutsStore{Store: auto}}, want: nil},
		{name: "auto from store", cfg: &config{store: auto}, want: auto.AuthnLockouts()},
		{
			name: "explicit wins over store",
			cfg:  &config{store: auto, authnLockoutStore: explicit},
			want: explicit,
		},
		{
			name: "explicit without store",
			cfg:  &config{authnLockoutStore: explicit},
			want: explicit,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := resolveAuthnLockoutStore(tc.cfg); got != tc.want {
				t.Fatalf("resolveAuthnLockoutStore = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestCompile_StepErrorWinsOverMissingLockoutStore pins that a step's own
// configuration error is reported ahead of the missing lockout store.
func TestCompile_StepErrorWinsOverMissingLockoutStore(t *testing.T) {
	t.Parallel()

	inner := inmem.New()
	flow := LoginFlow{
		Primary: PrimaryPassword{Store: inner.UserPasswords()},
		Rules:   []Rule{RuleAlways(StepTOTP{Store: inner.TOTPs()})}, // no encryption key
	}
	cfg := &config{store: noLockoutsStore{Store: inner}, loginFlow: flow, loginFlowSet: true}
	_, err := compileLoginFlow(flow, cfg)
	if err == nil {
		t.Fatal("compileLoginFlow: want error, got nil")
	}
	if errors.Is(err, ErrAuthnLockoutStoreRequired) {
		t.Fatalf("compileLoginFlow err = %v, want the StepTOTP key error", err)
	}
	if !strings.Contains(err.Error(), "StepTOTP.EncryptionKey is required") {
		t.Fatalf("compileLoginFlow err = %v, want StepTOTP key error", err)
	}
}

// TestCompile_RequiresLockoutStore pins that compiling a login flow with a
// counter-consuming step fails with ErrAuthnLockoutStoreRequired when no
// lockout store resolves, and succeeds when one does.
func TestCompile_RequiresLockoutStore(t *testing.T) {
	t.Parallel()

	inner := inmem.New()
	totpKey := stubTOTPKey("totp-warn-key")
	flow := LoginFlow{
		Primary: PrimaryPassword{Store: inner.UserPasswords()},
		Rules:   []Rule{RuleAlways(StepTOTP{Store: inner.TOTPs(), EncryptionKey: totpKey})},
	}

	cases := []struct {
		name     string
		store    store.Store
		explicit store.AuthnLockoutStore
		wantErr  bool
	}{
		{name: "no accessor", store: noLockoutsStore{Store: inner}, wantErr: true},
		{name: "accessor returns nil", store: nilLockoutsStore{Store: inner}, wantErr: true},
		{name: "auto-wired", store: inner},
		{name: "explicit", store: noLockoutsStore{Store: inner}, explicit: inner.AuthnLockouts()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config{
				store:             tc.store,
				authnLockoutStore: tc.explicit,
				loginFlow:         flow,
				loginFlowSet:      true,
			}
			_, err := compileLoginFlow(flow, cfg)
			if tc.wantErr {
				if !errors.Is(err, ErrAuthnLockoutStoreRequired) {
					t.Fatalf("compileLoginFlow err = %v, want ErrAuthnLockoutStoreRequired", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("compileLoginFlow: %v", err)
			}
		})
	}
}
