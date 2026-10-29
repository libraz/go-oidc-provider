package emailotp_test

import (
	"context"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/emailotp"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestEnrolled_EmailBound pins that a subject counts as enrolled only
// with an email claim bound.
func TestEnrolled_EmailBound(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	clock := &emailotp.FakeClock{T: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)}
	st := inmem.New(inmem.WithClock(clock))
	st.PutUser(ctx, &store.User{Subject: "sub-bound", Claims: map[string]any{"email": "alice@example.com"}})
	st.PutUser(ctx, &store.User{Subject: "sub-unbound", Claims: map[string]any{}})
	a, err := emailotp.NewAuthenticator(emailotp.Config{
		Mailer: &recordingMailer{}, Store: st.EmailOTPs(), Users: st.Users(), Clock: clock, SendLatencyPad: -1,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	for subject, want := range map[string]bool{"sub-bound": true, "sub-unbound": false, "sub-unknown": false} {
		got, err := a.Enrolled(ctx, subject)
		if err != nil {
			t.Fatalf("Enrolled(%q): %v", subject, err)
		}
		if got != want {
			t.Errorf("Enrolled(%q) = %v, want %v", subject, got, want)
		}
	}
}
