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
