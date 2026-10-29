package emailotp_test

import (
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

// TestBegin_NotEnrolledIsFactorAbort pins that a subject with no bound
// email claim is refused with ErrEmailNotBound, which is both an
// ErrFactorNotEnrolled and an ErrFactorAbort so it renders as a 4xx.
func TestBegin_NotEnrolledIsFactorAbort(t *testing.T) {
	t.Parallel()

	clock := &emailotp.FakeClock{T: time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)}
	st := inmem.New(inmem.WithClock(clock))
	users := &fakeUsers{users: map[string]*store.User{
		"sub-1": {Subject: "sub-1", Claims: map[string]any{}},
	}}
	a, err := emailotp.NewAuthenticator(emailotp.Config{
		Mailer: &recordingMailer{}, Store: st.EmailOTPs(), Users: users, Clock: clock, SendLatencyPad: -1,
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}

	_, err = a.Continue(context.Background(), authn.ContinueInput{
		Subject: "sub-1",
		Submission: interaction.FormSubmission{Values: map[string]string{
			emailotp.EmailFieldName: "alice@example.com",
		}},
	})
	if !errors.Is(err, emailotp.ErrEmailNotBound) {
		t.Fatalf("err = %v, want ErrEmailNotBound", err)
	}
	if !errors.Is(emailotp.ErrEmailNotBound, authn.ErrFactorNotEnrolled) {
		t.Error("ErrEmailNotBound must wrap ErrFactorNotEnrolled")
	}
	if !errors.Is(emailotp.ErrEmailNotBound, authn.ErrFactorAbort) {
		t.Error("ErrEmailNotBound must wrap ErrFactorAbort")
	}
}
