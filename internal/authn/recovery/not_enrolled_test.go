package recovery_test

import (
	"context"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/op"
)

// TestBegin_NotEnrolledIsFactorAbort pins that Begin refuses, without a
// prompt, a subject that has no recovery batch, and that the refusal is an
// ErrFactorAbort so it renders as a 4xx rather than a 500.
func TestBegin_NotEnrolledIsFactorAbort(t *testing.T) {
	t.Parallel()

	f := newAdapterFixture(t)
	step, err := f.adapter.Begin(context.Background(), op.BeginInput{
		Subject:  "user-unknown",
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
}
