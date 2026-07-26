package emailotp_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/emailotp"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestSend_RejectsResendBeforeMinInterval asserts that a second send
// within [resendMinInterval] is rejected as ErrTooManyOutstanding so an
// attacker cannot flood the SMTP path.
func TestSend_RejectsResendBeforeMinInterval(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	a, _, _ := newFixture(t, now)

	// First send succeeds.
	first := sendOnce(t, a, "alice@example.com")
	if first.Prompt == nil || first.Prompt.Type != emailotp.PromptTypeVerify {
		t.Fatalf("first send: prompt = %+v, want verify", first.Prompt)
	}

	// Second send within 30s is rejected. The clock has not moved
	// (FakeClock holds the same instant) so the elapsed time is
	// strictly zero — well below the 30s floor.
	_, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject: "sub-1",
		Submission: interaction.FormSubmission{Values: map[string]string{
			emailotp.EmailFieldName: "alice@example.com",
		}},
	})
	if !errors.Is(err, emailotp.ErrTooManyOutstanding) {
		t.Errorf("second send err = %v, want ErrTooManyOutstanding", err)
	}
}

// TestSend_AllowsResendAfterMinInterval asserts the gate releases once
// the minimum interval has elapsed.
func TestSend_AllowsResendAfterMinInterval(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	clock := &emailotp.FakeClock{T: now}
	a := newFixtureWithClock(t, clock)

	if _, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject: "sub-1",
		Submission: interaction.FormSubmission{Values: map[string]string{
			emailotp.EmailFieldName: "alice@example.com",
		}},
	}); err != nil {
		t.Fatalf("first send: %v", err)
	}

	// Move clock past the 30s floor.
	clock.T = now.Add(31 * time.Second)
	if _, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject: "sub-1",
		Submission: interaction.FormSubmission{Values: map[string]string{
			emailotp.EmailFieldName: "alice@example.com",
		}},
	}); err != nil {
		t.Errorf("post-cooldown send err = %v, want nil", err)
	}
}

// TestSend_RejectsAfterWindowCap asserts the window cap: more than
// [resendWindowCap] sends within the rolling window are rejected.
func TestSend_RejectsAfterWindowCap(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	clock := &emailotp.FakeClock{T: now}
	a := newFixtureWithClock(t, clock)

	// Five sends spaced 31 seconds apart all succeed (under the
	// rolling-window cap of 5).
	for i := range 5 {
		clock.T = now.Add(time.Duration(i) * 31 * time.Second)
		if _, err := a.Continue(context.Background(), authn.ContinueInput{
			Subject: "sub-1",
			Submission: interaction.FormSubmission{Values: map[string]string{
				emailotp.EmailFieldName: "alice@example.com",
			}},
		}); err != nil {
			t.Fatalf("send #%d: err = %v, want nil", i+1, err)
		}
	}

	// Sixth send within the same 1h window is rejected.
	clock.T = now.Add(5 * 31 * time.Second)
	_, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject: "sub-1",
		Submission: interaction.FormSubmission{Values: map[string]string{
			emailotp.EmailFieldName: "alice@example.com",
		}},
	})
	if !errors.Is(err, emailotp.ErrTooManyOutstanding) {
		t.Errorf("sixth send err = %v, want ErrTooManyOutstanding", err)
	}
}

// TestSend_WindowRollsOverAfterOneHour asserts a send that lands
// outside the rolling window resets the counter.
func TestSend_WindowRollsOverAfterOneHour(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	clock := &emailotp.FakeClock{T: now}
	a := newFixtureWithClock(t, clock)

	// Five sends at the cap; further sends inside the window fail.
	for i := range 5 {
		clock.T = now.Add(time.Duration(i) * 31 * time.Second)
		if _, err := a.Continue(context.Background(), authn.ContinueInput{
			Subject: "sub-1",
			Submission: interaction.FormSubmission{Values: map[string]string{
				emailotp.EmailFieldName: "alice@example.com",
			}},
		}); err != nil {
			t.Fatalf("send #%d: %v", i+1, err)
		}
	}

	// Move past the window. The next send must succeed; the counter
	// is reset internally.
	clock.T = now.Add(2 * time.Hour)
	if _, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject: "sub-1",
		Submission: interaction.FormSubmission{Values: map[string]string{
			emailotp.EmailFieldName: "alice@example.com",
		}},
	}); err != nil {
		t.Errorf("post-window send err = %v, want nil", err)
	}
}

// TestSend_WindowCapAppliesToUnmatchedEmail asserts that the
// unmatched-email branch (which skips the mailer) still increments the
// counter so an attacker cannot trivially circumvent the rate limit by
// sending wrong emails.
func TestSend_WindowCapAppliesToUnmatchedEmail(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	clock := &emailotp.FakeClock{T: now}
	a := newFixtureWithClock(t, clock)

	for i := range 5 {
		clock.T = now.Add(time.Duration(i) * 31 * time.Second)
		if _, err := a.Continue(context.Background(), authn.ContinueInput{
			Subject: "sub-1",
			Submission: interaction.FormSubmission{Values: map[string]string{
				emailotp.EmailFieldName: "intruder@example.com",
			}},
		}); err != nil {
			t.Fatalf("unmatched send #%d: %v", i+1, err)
		}
	}
	clock.T = now.Add(5 * 31 * time.Second)
	_, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject: "sub-1",
		Submission: interaction.FormSubmission{Values: map[string]string{
			emailotp.EmailFieldName: "alice@example.com",
		}},
	})
	if !errors.Is(err, emailotp.ErrTooManyOutstanding) {
		t.Errorf("matched send after 5 unmatched err = %v, want ErrTooManyOutstanding", err)
	}
}

// TestSend_MinIntervalAppliesToUnmatchedEmail asserts that
// the minimum-interval gate fires regardless of whether the prior
// send hit the matched (mailer-invoked) or unmatched (mailer-skipped)
// branch. The unmatched branch leaves SentAt zero by design, but the
// LastSendAttemptAt stamp tracks every attempt so an attacker cannot
// trivially bypass the floor by spamming wrong addresses.
func TestSend_MinIntervalAppliesToUnmatchedEmail(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	a, _, _ := newFixture(t, now)

	// First send with an unmatched address: SentAt stays zero, but
	// LastSendAttemptAt is stamped to now.
	if _, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject: "sub-1",
		Submission: interaction.FormSubmission{Values: map[string]string{
			emailotp.EmailFieldName: "intruder@example.com",
		}},
	}); err != nil {
		t.Fatalf("first unmatched send: %v", err)
	}
	// Quick resend (clock unchanged) MUST be rejected even though
	// the first send did NOT trigger the mailer.
	_, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject: "sub-1",
		Submission: interaction.FormSubmission{Values: map[string]string{
			emailotp.EmailFieldName: "alice@example.com",
		}},
	})
	if !errors.Is(err, emailotp.ErrTooManyOutstanding) {
		t.Errorf("post-unmatched matched resend err = %v, want ErrTooManyOutstanding", err)
	}
}

// TestSend_PriorRecordIsNotOverwrittenByQuickResend asserts that a
// resend within the rate-limit floor does NOT overwrite the prior
// record. The prior CodeHash and SentAt must survive so the verify
// endpoint cannot race a fresh code against the old one.
func TestSend_PriorRecordIsNotOverwrittenByQuickResend(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	a, _, recStore := newFixture(t, now)

	if _, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject: "sub-1",
		Submission: interaction.FormSubmission{Values: map[string]string{
			emailotp.EmailFieldName: "alice@example.com",
		}},
	}); err != nil {
		t.Fatalf("first send: %v", err)
	}
	first, err := recStore.Get(context.Background(), "sub-1")
	if err != nil {
		t.Fatalf("get first record: %v", err)
	}
	firstHash := append([]byte(nil), first.CodeHash...)
	firstSentAt := first.SentAt

	// Quick resend should be rejected and must NOT touch the record.
	if _, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject: "sub-1",
		Submission: interaction.FormSubmission{Values: map[string]string{
			emailotp.EmailFieldName: "alice@example.com",
		}},
	}); !errors.Is(err, emailotp.ErrTooManyOutstanding) {
		t.Fatalf("quick resend err = %v, want ErrTooManyOutstanding", err)
	}
	second, err := recStore.Get(context.Background(), "sub-1")
	if err != nil {
		t.Fatalf("get second record: %v", err)
	}
	if !bytes.Equal(second.CodeHash, firstHash) {
		t.Errorf("CodeHash mutated by rejected resend: prior overwrite leak")
	}
	if !second.SentAt.Equal(firstSentAt) {
		t.Errorf("SentAt mutated by rejected resend: prior overwrite leak")
	}
}

// TestSend_WindowCapSurvivesCodeExpiry pins the #16 fix: an attacker who
// exhausts the resend cap and then paces just past the code TTL (so the
// code record would previously be read as absent) MUST still be blocked
// while inside the 1-hour resend window. Before the RetainUntil retention
// fix, the record vanished at code expiry, the resend counter reset, and
// the cap degraded from 5/hour to roughly 5 per code-TTL.
func TestSend_WindowCapSurvivesCodeExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)
	clock := &emailotp.FakeClock{T: now}
	a := newFixtureWithClock(t, clock)

	// Five sends reach the rolling-window cap.
	for i := range 5 {
		clock.T = now.Add(time.Duration(i) * 31 * time.Second)
		if _, err := a.Continue(context.Background(), authn.ContinueInput{
			Subject: "sub-1",
			Submission: interaction.FormSubmission{Values: map[string]string{
				emailotp.EmailFieldName: "alice@example.com",
			}},
		}); err != nil {
			t.Fatalf("send #%d: %v", i+1, err)
		}
	}

	// Advance past the code TTL (so the code itself is dead) but well
	// within both the 1-hour resend window and the record retention.
	clock.T = now.Add(emailotp.DefaultCodeTTL + time.Minute)

	// The sixth send must still be rejected: the cap did not reset.
	_, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject: "sub-1",
		Submission: interaction.FormSubmission{Values: map[string]string{
			emailotp.EmailFieldName: "alice@example.com",
		}},
	})
	if !errors.Is(err, emailotp.ErrTooManyOutstanding) {
		t.Errorf("post-code-expiry send err = %v, want ErrTooManyOutstanding (cap must survive code expiry)", err)
	}
}

func sendOnce(t *testing.T, a *emailotp.Authenticator, email string) interaction.Step {
	t.Helper()
	step, err := a.Continue(context.Background(), authn.ContinueInput{
		Subject: "sub-1",
		Submission: interaction.FormSubmission{Values: map[string]string{
			emailotp.EmailFieldName: email,
		}},
	})
	if err != nil {
		t.Fatalf("Continue (send): %v", err)
	}
	return step
}

func newFixtureWithClock(t *testing.T, clock *emailotp.FakeClock) *emailotp.Authenticator {
	t.Helper()
	st := inmem.New(inmem.WithClock(clock))
	users := &fakeUsers{
		users: map[string]*store.User{
			"sub-1": {Subject: "sub-1", Claims: map[string]any{"email": "alice@example.com"}},
		},
	}
	mailer := &recordingMailer{}
	a, err := emailotp.NewAuthenticator(emailotp.Config{
		Mailer:         mailer,
		Store:          st.EmailOTPs(),
		Users:          users,
		Clock:          clock,
		SendLatencyPad: -1,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return a
}
