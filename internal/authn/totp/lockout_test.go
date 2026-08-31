package totp_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestAuthenticator_CrossFactorLockoutSurfacesAsErrLocked covers the
// cross-factor budget from the TOTP side: the authenticator MUST
// surface the cross-factor [lockout.Counter] verdict as
// [totp.ErrLocked] so the orchestrator dispatches the same way it
// does for the per-factor lock. The test pre-saturates the
// cross-factor counter with 30 failures (the short threshold) against
// an external subject, then asserts the next TOTP Continue returns
// ErrLocked even though the per-record FailedCount sits at zero.
func TestAuthenticator_CrossFactorLockoutSurfacesAsErrLocked(t *testing.T) {
	t.Parallel()

	subject := "alice"
	st := inmem.New()

	// Pre-saturate the cross-factor counter to the short threshold
	// without going through the TOTP authenticator (so the per-record
	// FailedCount stays at zero).
	counter, err := lockout.New(st.AuthnLockouts(), nil)
	if err != nil {
		t.Fatalf("lockout.New: %v", err)
	}
	for i := 1; i <= 30; i++ {
		if _, err := counter.RecordFailure(context.Background(), subject); err != nil {
			t.Fatalf("RecordFailure %d: %v", i, err)
		}
	}

	// Seed a confirmed TOTP record so the verify path runs (a missing
	// record short-circuits before the lockout gate).
	codec, err := totp.NewCodec(make([]byte, 32))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	blob, err := codec.Seal(secret, []byte(subject))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	if err := st.TOTPs().Put(context.Background(), &store.TOTPRecord{
		Subject:          subject,
		SecretCiphertext: blob,
		ConfirmedAt:      now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("TOTPs.Put: %v", err)
	}

	verifier := &totp.Verifier{Codec: codec}
	auth, err := totp.NewAuthenticator(verifier, st.TOTPs())
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	auth = auth.WithLockout(counter)

	// Begin must surface the lock.
	_, err = auth.Begin(context.Background(), authn.BeginInput{
		Subject:  subject,
		AuthTime: now,
	})
	if !errors.Is(err, totp.ErrLocked) {
		t.Fatalf("Begin err=%v want ErrLocked", err)
	}

	// Continue must surface the lock too — even with a wrong-code
	// submission that would otherwise hit the per-record verifier.
	_, err = auth.Continue(context.Background(), authn.ContinueInput{
		Subject: subject,
		Submission: interaction.FormSubmission{
			Values: map[string]string{
				totp.CodeFieldName: "000000",
			},
		},
	})
	if !errors.Is(err, totp.ErrLocked) {
		t.Fatalf("Continue err=%v want ErrLocked", err)
	}
}

// TestAuthenticator_ExpiredCrossFactorLockDoesNotResurrect covers what
// the user actually experiences once a cross-factor lock has served its
// time. The counter is saturated from a sibling factor, then both the
// 1-hour lock and the 24-hour counter window are allowed to elapse. The
// next wrong code must be a recoverable retry: it starts a fresh budget
// and crosses no threshold, so nothing may re-adopt the spent lock
// stamp. Were it re-adopted, the failure would come back as
// [totp.ErrLocked], the chain would abort, and the user would be told
// their account is locked on every subsequent attempt — including the
// ones with a correct code, since Begin is gated too.
func TestAuthenticator_ExpiredCrossFactorLockDoesNotResurrect(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	subject := "alice"
	st := inmem.New()
	clock := &fakeClock{t: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)}

	counter, err := lockout.New(st.AuthnLockouts(), clock)
	if err != nil {
		t.Fatalf("lockout.New: %v", err)
	}
	// Saturate the shared counter to the short threshold from a sibling
	// factor, so the TOTP record's own FailedCount stays at zero and the
	// cross-factor stamp is the only lock in play.
	for i := 1; i <= 30; i++ {
		if _, err := counter.RecordFailure(ctx, subject); err != nil {
			t.Fatalf("RecordFailure %d: %v", i, err)
		}
	}

	codec, err := totp.NewCodec(newKey(t))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	rec := newRecord(t, codec, subject, secret, clock.t.Add(-time.Hour))
	if err := st.TOTPs().Put(ctx, rec); err != nil {
		t.Fatalf("TOTPs.Put: %v", err)
	}
	auth, err := totp.NewAuthenticator(&totp.Verifier{Clock: clock, Codec: codec}, st.TOTPs())
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	auth = auth.WithLockout(counter)

	if _, err := auth.Begin(ctx, authn.BeginInput{Subject: subject, AuthTime: clock.t}); !errors.Is(err, totp.ErrLocked) {
		t.Fatalf("Begin while the lock runs: err=%v want ErrLocked", err)
	}

	// Past the 1-hour lock and past the 24-hour counter window.
	clock.t = clock.t.Add(25 * time.Hour)
	if _, err := auth.Begin(ctx, authn.BeginInput{Subject: subject, AuthTime: clock.t}); err != nil {
		t.Fatalf("Begin after the lock expired: %v; want the prompt back", err)
	}

	wrong := "000000"
	for _, offset := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		if totp.Code(secret, clock.t.Add(offset)) == wrong {
			wrong = "999999"
		}
	}
	submission := interaction.FormSubmission{Values: map[string]string{totp.CodeFieldName: wrong}}
	_, err = auth.Continue(ctx, authn.ContinueInput{Subject: subject, AuthTime: clock.t, Submission: submission})
	if errors.Is(err, totp.ErrLocked) {
		t.Fatalf("first wrong code after the lock expired reported the account as locked: %v", err)
	}
	if !errors.Is(err, totp.ErrRetry) {
		t.Fatalf("Continue err=%v want ErrRetry", err)
	}

	// The verdict must also not have been persisted: a stamp written
	// back to the row would lock the very next Begin instead.
	if _, err := auth.Begin(ctx, authn.BeginInput{Subject: subject, AuthTime: clock.t}); err != nil {
		t.Fatalf("Begin after a recoverable wrong code: %v; want the prompt back", err)
	}
}

// crossFactorFailures reports the cumulative count the shared counter
// holds for subject. A missing row is the "never failed" state and reads
// as zero.
func crossFactorFailures(t *testing.T, lockouts store.AuthnLockoutStore, subject string) int {
	t.Helper()

	rec, err := lockouts.Get(context.Background(), subject)
	if errors.Is(err, store.ErrNotFound) {
		return 0
	}
	if err != nil {
		t.Fatalf("AuthnLockouts.Get: %v", err)
	}
	return rec.FailedCount
}

// TestAuthenticator_ReplayDoesNotAdvanceCrossFactorCounter pins the
// promise the replay guard makes: a code the record has already accepted
// is a double-submitted form or a browser retry, not a guess, so no
// brute-force counter it can reach may advance — neither the per-record
// FailedCount nor the cross-factor budget shared with the sibling
// factors. Without this, a flaky connection spends a legitimate user's
// way towards a one-hour lock on submissions they made only once.
//
// A genuine wrong code is driven through the same authenticator
// afterwards so the zero asserted above is a property of the replay
// path, not of a counter that was never wired.
func TestAuthenticator_ReplayDoesNotAdvanceCrossFactorCounter(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	subject := "alice"
	st := inmem.New()
	clock := &fakeClock{t: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)}

	counter, err := lockout.New(st.AuthnLockouts(), clock)
	if err != nil {
		t.Fatalf("lockout.New: %v", err)
	}
	codec, err := totp.NewCodec(newKey(t))
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	if err := st.TOTPs().Put(ctx, newRecord(t, codec, subject, secret, clock.t.Add(-time.Hour))); err != nil {
		t.Fatalf("TOTPs.Put: %v", err)
	}
	auth, err := totp.NewAuthenticator(&totp.Verifier{Clock: clock, Codec: codec}, st.TOTPs())
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	auth = auth.WithLockout(counter)

	code := totp.Code(secret, clock.t)
	submission := interaction.FormSubmission{Values: map[string]string{totp.CodeFieldName: code}}

	step, err := auth.Continue(ctx, authn.ContinueInput{Subject: subject, AuthTime: clock.t, Submission: submission})
	if err != nil {
		t.Fatalf("first submission: %v", err)
	}
	if step.Result == nil {
		t.Fatalf("first submission returned %+v, want a Result", step)
	}

	// The same code again, inside the same step window: the replay guard
	// refuses it, and the refusal must be a soft retry.
	_, err = auth.Continue(ctx, authn.ContinueInput{Subject: subject, AuthTime: clock.t, Submission: submission})
	if !errors.Is(err, totp.ErrRetry) {
		t.Fatalf("replayed submission err=%v want ErrRetry", err)
	}
	if got := crossFactorFailures(t, st.AuthnLockouts(), subject); got != 0 {
		t.Errorf("cross-factor FailedCount after a replay = %d, want 0: a replay is not a guess and must not "+
			"spend the budget shared with every other factor", got)
	}
	rec, err := st.TOTPs().Get(ctx, subject)
	if err != nil {
		t.Fatalf("TOTPs.Get: %v", err)
	}
	if rec.FailedCount != 0 {
		t.Errorf("record FailedCount after a replay = %d, want 0", rec.FailedCount)
	}

	// Control: a code that never matched is a guess, and the shared
	// counter does move for it.
	wrong := "000000"
	for _, offset := range []time.Duration{-30 * time.Second, 0, 30 * time.Second} {
		if totp.Code(secret, clock.t.Add(offset)) == wrong {
			wrong = "999999"
		}
	}
	_, err = auth.Continue(ctx, authn.ContinueInput{
		Subject:    subject,
		AuthTime:   clock.t,
		Submission: interaction.FormSubmission{Values: map[string]string{totp.CodeFieldName: wrong}},
	})
	if !errors.Is(err, totp.ErrRetry) {
		t.Fatalf("wrong-code submission err=%v want ErrRetry", err)
	}
	if got := crossFactorFailures(t, st.AuthnLockouts(), subject); got != 1 {
		t.Errorf("cross-factor FailedCount after a real wrong code = %d, want 1", got)
	}
}
