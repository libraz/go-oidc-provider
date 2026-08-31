package testkit

import (
	"net/http"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// AutoConsentDriver is the [interaction.Driver] the testkit installs by
// default. It delegates prompt rendering and submission parsing verbatim
// to the stock [interaction.JSONDriver]; the testkit value exists to keep
// the wiring in [NewProvider] readable and to give third-party tests a
// single import path for the default driver.
//
// Despite the name it approves nothing. A prompted authorization stops
// at the interaction endpoint with a 200 and a JSON prompt body, not a
// 302, and the test must submit the consent itself — see
// [PostConsentApproval]. Only a flow that needs no prompt at all (a
// first-party client, or a grant that already covers the requested
// scope) reaches the redirect without that step. The name is retained
// for compatibility with the v1.0 stable surface.
//
// Tests that need a different shape (custom rendering, multi-step
// flows) install their own driver via [op.WithInteractionDriver] passed
// through [WithOptions].
//
// AutoConsentDriver is safe for concurrent use; it carries no state.
type AutoConsentDriver struct{}

// Render implements [interaction.Driver] by delegating to
// [interaction.JSONDriver.Render].
func (AutoConsentDriver) Render(w http.ResponseWriter, r *http.Request, prompt interaction.Prompt) error {
	return interaction.JSONDriver{}.Render(w, r, prompt)
}

// ParseSubmission implements [interaction.Driver] by delegating to
// [interaction.JSONDriver.ParseSubmission].
func (AutoConsentDriver) ParseSubmission(r *http.Request) (interaction.FormSubmission, error) {
	return interaction.JSONDriver{}.ParseSubmission(r)
}

// Compile-time confirmation that AutoConsentDriver satisfies the
// driver contract.
var _ interaction.Driver = AutoConsentDriver{}
