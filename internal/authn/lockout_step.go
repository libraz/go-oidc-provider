package authn

import (
	"context"
	"errors"
	"fmt"

	"github.com/libraz/go-oidc-provider/internal/authn/lockout"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// Terminal errors of a lockout-wrapped step's Continue. Both follow an
// evaluated wrong guess, so they carry [ErrCredentialRejected].
var (
	errLockoutEngaged       = fmt.Errorf("authn: factor locked: %w: %w", ErrFactorLocked, ErrCredentialRejected)
	errLockoutResetRequired = fmt.Errorf("authn: factor reset required: %w: %w", ErrFactorAbort, ErrCredentialRejected)
)

// WithLockoutCounter returns auth gated by the cross-factor brute-force
// counter c, the way the built-in second factors gate themselves: a
// locked subject is refused with [ErrFactorLocked] before Begin and
// Continue run, a Continue that reports [ErrFactorRetry] counts one
// failure (a retry carrying a re-prompt included), and a Continue that
// completes resets the count. The optional [EnrollmentProber] and
// [UserVerificationReporter] of auth stay visible on the result. A nil c
// returns auth unchanged.
func WithLockoutCounter(auth Authenticator, c *lockout.Counter) Authenticator { //nolint:ireturn,nolintlint // the wrapper's shape depends on which optional interfaces auth implements.
	if c == nil {
		return auth
	}
	base := &lockoutStep{Authenticator: auth, counter: c}
	prober, isProber := auth.(EnrollmentProber)
	reporter, isReporter := auth.(UserVerificationReporter)
	switch {
	case isProber && isReporter:
		return struct {
			*lockoutStep
			EnrollmentProber
			UserVerificationReporter
		}{base, prober, reporter}
	case isProber:
		return struct {
			*lockoutStep
			EnrollmentProber
		}{base, prober}
	case isReporter:
		return struct {
			*lockoutStep
			UserVerificationReporter
		}{base, reporter}
	default:
		return base
	}
}

// lockoutStep is the [WithLockoutCounter] wrapper. Type, AAL, AMR and
// Prompts pass through to the wrapped authenticator.
type lockoutStep struct {
	Authenticator
	counter *lockout.Counter
}

// Begin implements [Authenticator].
func (s *lockoutStep) Begin(ctx context.Context, in BeginInput) (interaction.Step, error) {
	if err := s.guard(ctx, in.Subject); err != nil {
		return interaction.Step{}, err
	}
	return s.Authenticator.Begin(ctx, in)
}

// Continue implements [Authenticator].
func (s *lockoutStep) Continue(ctx context.Context, in ContinueInput) (interaction.Step, error) {
	if err := s.guard(ctx, in.Subject); err != nil {
		return interaction.Step{}, err
	}
	step, err := s.Authenticator.Continue(ctx, in)
	switch {
	case err == nil && step.Result != nil:
		if rerr := s.counter.Reset(ctx, in.Subject); rerr != nil {
			return interaction.Step{}, fmt.Errorf("authn: lockout reset: %w", rerr)
		}
	case err != nil && classifyFactorError(err) == credentialRejected:
		out, lerr := s.counter.RecordFailure(ctx, in.Subject)
		if lerr != nil {
			return interaction.Step{}, fmt.Errorf("authn: lockout record failure: %w", lerr)
		}
		if out.ResetRequired {
			return interaction.Step{}, errLockoutResetRequired
		}
		// The counter reports an expired lock as zero, so a non-zero
		// stamp is a lock in force.
		if !out.LockedUntil.IsZero() {
			return interaction.Step{}, errLockoutEngaged
		}
	}
	return step, err
}

// guard refuses a subject the cross-factor counter has locked.
func (s *lockoutStep) guard(ctx context.Context, subject string) error {
	err := s.counter.GuardBegin(ctx, subject)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, lockout.ErrLocked):
		return ErrFactorLocked
	default:
		return fmt.Errorf("authn: lockout guard: %w", err)
	}
}
