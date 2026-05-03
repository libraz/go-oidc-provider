package emailotp_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/emailotp"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestSend_LatencyPadEqualisesMatchedAndUnmatched asserts H-E3: the
// matched-email branch (mailer invoked) and the unmatched-email branch
// (mailer skipped) both return after at least the configured floor so
// an attacker cannot enumerate registered subjects from response
// timing.
//
// The test uses real wall time (the latency pad blocks on
// time.NewTimer) and a short 50 ms pad so the suite runs quickly. We
// only assert the >= floor; we deliberately do NOT compare matched vs.
// unmatched to a tight delta because the mailer is a fast no-op on
// in-memory paths and the comparison would be flaky on busy CI.
func TestSend_LatencyPadEqualisesMatchedAndUnmatched(t *testing.T) {
	t.Parallel()
	const pad = 50 * time.Millisecond

	subjects := []struct {
		name  string
		email string
	}{
		{name: "matched", email: "alice@example.com"},
		{name: "unmatched", email: "intruder@example.com"},
	}

	for _, tc := range subjects {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			a := newPaddedFixture(t, pad)
			start := time.Now()
			_, err := a.Continue(context.Background(), authn.ContinueInput{
				Subject: "sub-1",
				Submission: interaction.FormSubmission{Values: map[string]string{
					emailotp.EmailFieldName: tc.email,
				}},
			})
			elapsed := time.Since(start)
			if err != nil {
				t.Fatalf("Continue (send): %v", err)
			}
			if elapsed < pad {
				t.Errorf("elapsed = %v, want >= %v (pad floor breached)", elapsed, pad)
			}
		})
	}
}

func newPaddedFixture(t *testing.T, pad time.Duration) *emailotp.Authenticator {
	t.Helper()
	// Use the system clock here: the latency pad uses time.NewTimer
	// against real wall time, so a frozen FakeClock would make the
	// pad block forever waiting for clock.Now() to advance past the
	// target. The test compensates by accepting a wider margin than
	// the unit tests do.
	st := inmem.New()
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
		Clock:          timex.SystemClock,
		SendLatencyPad: pad,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return a
}
