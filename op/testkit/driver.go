package testkit

import (
	"context"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// AutoConsentDriver is a permissive [interaction.Driver] tailored for tests.
// Unlike [interaction.NoopDriver] (which fails closed so production
// misconfigurations surface immediately), AutoConsentDriver accepts whatever
// the caller POSTs back to the /interaction/{uid} endpoint and signals the
// library to terminate the flow.
//
// The driver does not synthesize a subject by itself: tests still POST a
// [interaction.Result] body containing the subject_hint, granted_scopes, and
// auth_time they want recorded. AutoConsentDriver.Verify forwards that result
// verbatim to the library. Tests that need a different shape (multi-step
// flows, MFA fan-out) can install their own driver via
// [op.WithInteraction] passed through [WithOptions].
//
// AutoConsentDriver is safe for concurrent use; it carries no state.
type AutoConsentDriver struct{}

// Offer implements [interaction.Driver]. It returns a [interaction.PromptConsent]
// step with no follow-up reasons; tests typically render nothing for this
// prompt because they POST the [interaction.Result] directly.
func (AutoConsentDriver) Offer(_ context.Context, _ interaction.Request) (interaction.Step, error) {
	return interaction.Step{
		Hint: interaction.Hint{Prompt: interaction.PromptConsent},
	}, nil
}

// Verify implements [interaction.Driver]. It returns a terminal decision
// (Continue=false) so the library completes the flow with whatever Result the
// caller POSTed. The returned Decision carries no follow-up Step.
func (AutoConsentDriver) Verify(_ context.Context, _ interaction.Request, _ interaction.Result) (interaction.Decision, error) {
	return interaction.Decision{Continue: false}, nil
}

// Cancel implements [interaction.Driver] as a no-op so DELETE / abort tests
// succeed without side-effects.
func (AutoConsentDriver) Cancel(_ context.Context, _ interaction.Request) error { return nil }

// Compile-time confirmation that AutoConsentDriver satisfies the contract.
var _ interaction.Driver = AutoConsentDriver{}
