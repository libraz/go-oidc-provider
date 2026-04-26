package testkit

import (
	"net/http"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// AutoConsentDriver is a permissive [interaction.Driver] tailored for
// tests. It defers prompt rendering and submission parsing to the
// stock [interaction.JSONDriver]; the testkit value exists primarily
// to keep the wiring in [NewTest] readable and to give third-party
// tests a single import path for the default driver.
//
// Tests that need a different shape (custom rendering, multi-step
// flows) install their own driver via [op.WithInteraction] passed
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
