package main

import (
	"context"
	"strings"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// demoSubject is the single subject every successful login binds to.
// op-demo deliberately does not authenticate against a credential
// store: any non-empty (username, password) pair authenticates as
// demoSubject so OpenID Foundation Conformance Suite plans, which
// drive a browser through whatever credentials the operator types,
// can complete the chain without an embedder-supplied user database.
const demoSubject = "demo-user"

// stubAuthenticator is the [op.Authenticator] op-demo wires for the
// password factor. It exists so the binary can render and complete an
// interactive login without dragging a credential store, hashing
// machinery, or rate-limit policy into a dev demo. The tradeoff is
// honest: the only thing this factor proves is that a human typed
// something into the form.
type stubAuthenticator struct{}

// usernameField / passwordField are the [interaction.FieldSpec.Name]
// values the prompt declares. Exported as constants so the HTML driver
// can label them consistently and so a future test can target them
// without a stringly-typed copy.
const (
	usernameField = "username"
	passwordField = "password"
)

func (stubAuthenticator) Type() op.FactorType { return op.FactorPassword }
func (stubAuthenticator) AAL() op.AAL         { return op.AAL1 }
func (stubAuthenticator) AMR() string         { return "pwd" }
func (stubAuthenticator) Prompts() []string   { return []string{"auth.password"} }

// Begin emits the password prompt. The orchestrator persists
// [interaction.Prompt.StateRef] and routes the SPA's submission back
// to [Continue].
func (stubAuthenticator) Begin(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
	return interaction.Step{Prompt: passwordPrompt()}, nil
}

// Continue inspects the SPA submission. Any non-empty username and
// non-empty password complete the factor as [demoSubject]; an empty
// field re-emits the prompt. The library's [interaction.FieldSpec]
// validation already enforces minimum length, so the explicit check
// here is the trust-boundary belt over the orchestrator's braces.
func (stubAuthenticator) Continue(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
	user := strings.TrimSpace(in.Submission.Values[usernameField])
	pass := in.Submission.Values[passwordField]
	if user == "" || pass == "" {
		return interaction.Step{Prompt: passwordPrompt()}, nil
	}
	return interaction.Step{Result: &interaction.Result{
		Subject:  demoSubject,
		AuthTime: in.AuthTime,
	}}, nil
}

// passwordPrompt builds the password prompt the factor emits on Begin
// and on the empty-input retry branch of Continue. Centralising the
// shape here keeps the two call sites in sync.
func passwordPrompt() *interaction.Prompt {
	return &interaction.Prompt{
		Type: "auth.password",
		Data: interaction.PasswordPromptData{},
		Inputs: []interaction.FieldSpec{
			{Name: usernameField, Kind: interaction.FieldText, Label: "auth.password.username", Required: true, MinLen: 1, MaxLen: 64},
			{Name: passwordField, Kind: interaction.FieldPassword, Label: "auth.password.password", Required: true, MinLen: 1, MaxLen: 128},
		},
	}
}

// Compile-time confirmation that stubAuthenticator satisfies the
// public interface so a wiring drift surfaces at build rather than at
// the first conformance run.
var _ op.Authenticator = stubAuthenticator{}
