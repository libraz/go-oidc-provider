package testkit

import (
	"context"
	"errors"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// SubjectFieldName is the [interaction.FieldSpec.Name] [SubjectAuthenticator]
// expects in [interaction.FormSubmission.Values]. Tests echo the desired
// subject through this key; production deployments do not.
const SubjectFieldName = "subject"

// SubjectPromptType is the [interaction.Prompt.Type] [SubjectAuthenticator]
// emits. The "auth.testkit.subject" namespace marks it as a test-only
// extension so a deployment that accidentally registers
// [SubjectAuthenticator] in production is at least loud about it in
// audit logs.
const SubjectPromptType = "auth.testkit.subject"

// ErrSubjectMissing is returned by [SubjectAuthenticator.Continue]
// when the SPA does not echo a subject field.
var ErrSubjectMissing = errors.New("testkit: subject field is missing")

// SubjectAuthenticator is a test-only [op.Authenticator] that binds
// whatever subject the SPA submits. It exists for HTTP-layer tests
// that need a first-factor identifying step without the boilerplate
// of stubbing the whole interface every time. Production code MUST
// NOT register it: trusting a SPA-supplied subject is the inverse of
// authentication.
//
// The struct is safe for concurrent use; it carries no state.
type SubjectAuthenticator struct{}

// Type implements [op.Authenticator]. Returns a dotted-prefix value
// per [op.FactorType.IsUserDefined] so the testkit identifier never
// collides with a built-in [op.FactorType].
func (SubjectAuthenticator) Type() op.FactorType { return "testkit.subject" }

// AAL implements [op.Authenticator]. Returns [op.AAL1] — the lowest
// level — so a chain that mistakenly leaves the testkit factor in is
// reflected accurately in session metadata.
func (SubjectAuthenticator) AAL() op.AAL { return op.AAL1 }

// AMR implements [op.Authenticator]. Returns the empty string so the
// orchestrator drops the contribution rather than leaking a bogus
// RFC 8176 token into the amr_history claim.
func (SubjectAuthenticator) AMR() string { return "" }

// Prompts implements [op.Authenticator].
func (SubjectAuthenticator) Prompts() []string { return []string{SubjectPromptType} }

// Begin implements [op.Authenticator]. It emits a single prompt
// asking the SPA to echo a subject value. The prompt has no
// [interaction.PromptData] payload because the SPA sees only the [SubjectFieldName]
// input field.
func (SubjectAuthenticator) Begin(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
	return interaction.Step{Prompt: &interaction.Prompt{
		Type: SubjectPromptType,
		Inputs: []interaction.FieldSpec{{
			Name:     SubjectFieldName,
			Kind:     interaction.FieldText,
			Required: true,
			MinLen:   1,
			MaxLen:   256,
		}},
	}}, nil
}

// Continue implements [op.Authenticator]. It reads the subject field
// from the submission verbatim and stamps the orchestrator's
// reference clock onto [interaction.Result.AuthTime].
func (SubjectAuthenticator) Continue(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
	sub, ok := in.Submission.Values[SubjectFieldName]
	if !ok || sub == "" {
		return interaction.Step{}, ErrSubjectMissing
	}
	return interaction.Step{Result: &interaction.Result{Subject: sub, AuthTime: in.AuthTime}}, nil
}

// Compile-time confirmation that SubjectAuthenticator satisfies the
// public interface.
var _ op.Authenticator = SubjectAuthenticator{}
