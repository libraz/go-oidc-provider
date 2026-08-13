//go:build example

package main

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// pinnedClock keeps the seeded record inside its retention horizon
// whenever the test runs, so the store answers Get from the record's
// own fields rather than from the wall clock.
type pinnedClock struct{ now time.Time }

func (c pinnedClock) Now() time.Time { return c.now }

// TestFallbackToRecoveryCountsOnlyRejectedCodes pins the distinction
// the fallback rests on: the recovery sheet stands in for a mailbox
// that cannot be reached, so only a rejected mailed code may promote
// it. A password the user mistyped says nothing about their inbox, and
// a policy that counts it hands out the fallback to anyone who fumbles
// their password — the mailed factor never runs, and a second factor
// the flow declared is silently skipped.
//
// The counting is done for us: the e-mail OTP record carries its own
// verify-failure counter, which the login-wide submission count does
// not distinguish itself from.
func TestFallbackToRecoveryCountsOnlyRejectedCodes(t *testing.T) {
	t.Parallel()

	const subject = "demo-user"
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// afterPassword is the pass the orchestrator makes once the primary
	// step has bound the subject and the mailed code is the factor the
	// rule table is about to ask for.
	afterPassword := func(failedSubmissions int) op.LoginContext {
		return op.LoginContext{
			Identity:       op.Identity{Subject: subject},
			ClientID:       clientID,
			FailedAttempts: failedSubmissions,
			CompletedSteps: []op.StepKind{op.StepKindPassword},
		}
	}

	cases := []struct {
		name string
		// rejectedCodes is the mailed code's own failure count.
		// Negative means no record: nothing has been sent yet.
		rejectedCodes int
		lc            op.LoginContext
		want          op.Decision
	}{
		{
			name:          "password mistyped twice, no code sent yet",
			rejectedCodes: -1,
			lc:            afterPassword(2),
			want:          op.Pass{},
		},
		{
			name:          "password mistyped twice, first code still outstanding",
			rejectedCodes: 0,
			lc:            afterPassword(2),
			want:          op.Pass{},
		},
		{
			name:          "one code rejected",
			rejectedCodes: 1,
			lc:            afterPassword(1),
			want:          op.Pass{},
		},
		{
			name:          "two codes rejected",
			rejectedCodes: 2,
			lc:            afterPassword(2),
			want:          op.Require{Kind: op.StepKindRecoveryCode},
		},
		{
			name:          "recovery code already redeemed",
			rejectedCodes: 2,
			lc: op.LoginContext{
				Identity:       op.Identity{Subject: subject},
				ClientID:       clientID,
				FailedAttempts: 2,
				CompletedSteps: []op.StepKind{op.StepKindPassword, op.StepKindRecoveryCode},
			},
			want: op.Allow{},
		},
		{
			name:          "primary has not bound a subject yet",
			rejectedCodes: 2,
			lc:            op.LoginContext{ClientID: clientID, FailedAttempts: 2},
			want:          op.Pass{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			st := inmem.New(inmem.WithClock(pinnedClock{now: now}))
			if tc.rejectedCodes >= 0 {
				seedEmailOTPRecord(t, st.EmailOTPs(), subject, tc.rejectedCodes, now)
			}

			decider := fallbackToRecovery{otps: st.EmailOTPs(), after: 2}
			if got := decider.Decide(context.Background(), tc.lc); got != tc.want {
				t.Errorf("Decide() = %#v, want %#v (rejected codes: %d, rejected submissions: %d)",
					got, tc.want, tc.rejectedCodes, tc.lc.FailedAttempts)
			}
		})
	}
}

// TestFallbackToRecoveryPassesOnUnreadableRecord covers the store the
// Decider cannot read. An empty store answers ErrNotFound for every
// subject, which is the same answer an outage produces from the
// Decider's side. Neither says anything about the mailbox, so the flow
// keeps asking for the mailed code instead of promoting a sheet the
// user may never have been issued.
func TestFallbackToRecoveryPassesOnUnreadableRecord(t *testing.T) {
	t.Parallel()

	st := inmem.New(inmem.WithClock(pinnedClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}))
	decider := fallbackToRecovery{otps: st.EmailOTPs(), after: 1}

	lc := op.LoginContext{
		Identity:       op.Identity{Subject: "demo-user"},
		CompletedSteps: []op.StepKind{op.StepKindPassword},
		FailedAttempts: 9,
	}
	if got := decider.Decide(context.Background(), lc); got != (op.Pass{}) {
		t.Errorf("Decide() = %#v, want op.Pass{}", got)
	}
}

// seedEmailOTPRecord writes a pending challenge whose verify counter
// reads rejected. The hash fields are left empty on purpose: the
// Decider reads counters, and a record carrying a real code would put
// one in a test that has no use for it.
func seedEmailOTPRecord(tb testing.TB, otps store.EmailOTPStore, subject string, rejected int, now time.Time) {
	tb.Helper()

	rec := &store.EmailOTPRecord{
		Subject:     subject,
		SentAt:      now,
		ExpiresAt:   now.Add(10 * time.Minute),
		RetainUntil: now.Add(24 * time.Hour),
		FailedCount: rejected,
	}
	if rejected > 0 {
		rec.FirstFailureAt = now
	}
	if err := otps.Put(context.Background(), rec); err != nil {
		tb.Fatalf("seed email otp record: %v", err)
	}
}
