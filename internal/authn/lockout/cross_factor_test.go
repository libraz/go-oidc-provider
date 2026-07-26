package lockout_test

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestCrossFactorPivotTriggersLockout exercises the property that
// callers representing email-OTP and TOTP failures share one budget
// against the cross-factor counter. The test issues 3 failures attributed to
// "email-OTP" and 2 attributed to "TOTP" (total 5 < the short
// threshold), then asserts an additional 25 spread across the two
// adds up to 30 — the short-lock threshold — and the resulting
// LockedUntil stamp is in the future.
//
// The test deliberately does NOT mock the per-factor authenticators:
// it exercises the [lockout.Counter] directly. The counter is the
// shared point of authority for both factors; any future refactor
// that splits the counter into per-factor instances (which would
// defeat) breaks this test.
//
// Tracks: CVE-2026-9798 (Keycloak) — a CIBA authentication flow bypassed
// the brute-force account lockout that interactive login enforces, i.e.
// an alternate authentication flow received a separate brute-force
// budget. The structural property this pins is that every OP-side
// credential factor shares one per-subject counter with no notion of
// factor type, so no flow can obtain a fresh budget. (CIBA user
// authentication in this library is out-of-band on the authentication
// device, so it adds no separate OP-side credential-verification path to
// bypass; CIBA's own abuse surface is polling, gated separately by
// ciba.poll_abuse.lockout.)
func TestCrossFactorPivotTriggersLockout(t *testing.T) {
	t.Parallel()
	subject := "alice"
	st := inmem.New()
	counter, err := lockout.New(st.AuthnLockouts(), nil)
	if err != nil {
		t.Fatalf("lockout.New: %v", err)
	}

	// 3 "email-OTP" failures, 2 "TOTP" failures. The counter has no
	// notion of factor type; the test is symbolic.
	for i := 1; i <= 3; i++ {
		if _, err := counter.RecordFailure(context.Background(), subject); err != nil {
			t.Fatalf("emailotp attempt %d: %v", i, err)
		}
	}
	for i := 1; i <= 2; i++ {
		if _, err := counter.RecordFailure(context.Background(), subject); err != nil {
			t.Fatalf("totp attempt %d: %v", i, err)
		}
	}

	// Both factors should agree the counter is below the threshold.
	if err := counter.GuardBegin(context.Background(), subject); err != nil {
		t.Fatalf("GuardBegin under threshold: %v", err)
	}

	// Drive 25 more failures, half attributed to each factor, to reach
	// the short threshold of 30.
	for i := 1; i <= 13; i++ {
		if _, err := counter.RecordFailure(context.Background(), subject); err != nil {
			t.Fatalf("totp pivot attempt %d: %v", i, err)
		}
	}
	for i := 1; i <= 12; i++ {
		out, err := counter.RecordFailure(context.Background(), subject)
		if err != nil {
			t.Fatalf("emailotp pivot attempt %d: %v", i, err)
		}
		// On the last (cumulative #30) failure the short lock should
		// land. The threshold is inclusive at FailedCount >= 30.
		if out.FailedCount == 30 {
			if out.LockedUntil.IsZero() {
				t.Fatalf("LockedUntil zero at FailedCount=30")
			}
		}
	}

	// Now both factors must see the cross-factor lock.
	err = counter.GuardBegin(context.Background(), subject)
	if !errors.Is(err, lockout.ErrLocked) {
		t.Fatalf("GuardBegin after 30 cross-factor failures: err=%v want ErrLocked", err)
	}
	locked, until, err := counter.IsLocked(context.Background(), subject)
	if err != nil {
		t.Fatalf("IsLocked: %v", err)
	}
	if !locked {
		t.Fatal("IsLocked = false after threshold; want true")
	}
	if until.IsZero() {
		t.Fatal("IsLocked until zero; want a future timestamp")
	}
}
