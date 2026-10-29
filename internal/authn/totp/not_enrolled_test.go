package totp_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
)

// TestBegin_NotEnrolledIsFactorAbort pins that Begin refuses, without a
// prompt, a subject that has no enrolment or whose enrolment was never
// confirmed, and that the refusal is an ErrFactorAbort so it renders as a
// 4xx rather than a 500.
func TestBegin_NotEnrolledIsFactorAbort(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	secret := f.secret
	if err := f.store.Put(context.Background(), newRecord(t, f.codec, "user-pending", secret, time.Time{})); err != nil {
		t.Fatalf("Put: %v", err)
	}

	cases := []struct {
		name    string
		subject string
	}{
		{name: "no record", subject: "user-unknown"},
		{name: "unconfirmed record", subject: "user-pending"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			step, err := f.adapter.Begin(context.Background(), op.BeginInput{
				Subject:  tc.subject,
				AuthTime: f.authTime,
			})
			if !errors.Is(err, authn.ErrFactorNotEnrolled) {
				t.Fatalf("err = %v, want ErrFactorNotEnrolled", err)
			}
			if !errors.Is(err, authn.ErrFactorAbort) {
				t.Fatalf("err = %v, want it to wrap ErrFactorAbort", err)
			}
			if step.Prompt != nil {
				t.Fatalf("Begin emitted a prompt for an unenrolled subject: %+v", step.Prompt)
			}
		})
	}
}
