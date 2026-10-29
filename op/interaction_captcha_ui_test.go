package op_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// errCaptchaEmptyToken is the fixed rejection the fixture verifier
// returns; no test asserts on its text.
var errCaptchaEmptyToken = errors.New("empty captcha token")

// typedCaptchaVerifier accepts any non-empty token. It stands in for the
// deployments where the captcha is something a person reads and types,
// which is the case the warning below deliberately does not reject.
type typedCaptchaVerifier struct{}

func (typedCaptchaVerifier) Verify(_ context.Context, in op.CaptchaInput) error {
	if in.Token == "" {
		return errCaptchaEmptyToken
	}
	return nil
}

// scriptedDriver stands in for an embedder UI capable of mounting a
// provider widget. Its bodies are irrelevant; what matters is that the
// library must not assume anything about markup it did not write.
type scriptedDriver struct{}

func (scriptedDriver) Render(_ http.ResponseWriter, _ *http.Request, _ interaction.Prompt) error {
	return nil
}

func (scriptedDriver) ParseSubmission(_ *http.Request) (interaction.FormSubmission, error) {
	return interaction.FormSubmission{}, nil
}

// captchaFlowOpts is the option set the three cases below share: a
// password primary plus a captcha the rule list interposes after a few
// failures.
func captchaFlowOpts(tb testing.TB) []op.Option {
	tb.Helper()
	st := inmem.New()
	return append(validBaseOptsWithStoreNoAuthn(tb, st),
		op.WithLoginFlow(op.LoginFlow{
			Primary: op.PrimaryPassword{Store: st.UserPasswords()},
			Rules: []op.Rule{
				op.RuleAfterFailedAttempts(3, op.StepCaptcha{Verifier: typedCaptchaVerifier{}}),
			},
		}),
	)
}

// TestNew_WarnsWhenCaptchaRunsOnTheScriptlessHTMLSurface covers the
// combination the library cannot resolve on its own. The built-in HTML
// driver serves the captcha token field as a plain text input, so the
// challenge is answerable, but a token only a browser widget can mint is
// not something a user can type — and every request that reaches the
// gate is then refused for a reason nobody can act on.
// [op.CaptchaVerifier] is opaque, so the condition is reported rather
// than rejected: the deployments where a typed answer is the intended
// one keep working.
func TestNew_WarnsWhenCaptchaRunsOnTheScriptlessHTMLSurface(t *testing.T) {
	t.Parallel()

	logged := warnings(t, captchaFlowOpts(t)...)
	if !strings.Contains(logged, "built-in HTML driver") {
		t.Fatalf("no warning about the scriptless surface; got:\n%s", logged)
	}
}

// TestNew_DoesNotWarnAboutCaptchaOnAnEmbedderDriver is the half that
// keeps the warning worth reading: a Driver the library did not write
// may well mount the provider's widget, and warning about every one of
// them would train the reader to ignore the line.
func TestNew_DoesNotWarnAboutCaptchaOnAnEmbedderDriver(t *testing.T) {
	t.Parallel()

	logged := warnings(t, append(captchaFlowOpts(t), op.WithInteractionDriver(scriptedDriver{}))...)
	if strings.Contains(logged, "built-in HTML driver") {
		t.Fatalf("warned about a captcha behind an embedder driver; got:\n%s", logged)
	}
}

// TestNew_DoesNotWarnWithoutACaptcha pins the other trigger condition:
// the default HTML surface on its own is a supported configuration and
// says nothing.
func TestNew_DoesNotWarnWithoutACaptcha(t *testing.T) {
	t.Parallel()

	logged := warnings(t, validBaseOpts(t)...)
	if strings.Contains(logged, "built-in HTML driver") {
		t.Fatalf("warned with no captcha configured; got:\n%s", logged)
	}
}

// passkeyFlowOpts is a login flow that runs the WebAuthn ceremony as a
// rule step after the primary.
func passkeyFlowOpts(tb testing.TB) []op.Option {
	tb.Helper()
	st := inmem.New()
	return append(validBaseOptsWithStoreNoAuthn(tb, st),
		op.WithLoginFlow(flowWithRule(op.PrimaryPasskey{
			Store:         st.Passkeys(),
			RPID:          "id.example.com",
			RPDisplayName: "Example",
			RPOrigins:     []string{"https://id.example.com"},
		})),
	)
}

// TestNew_DoesNotWarnAboutPasskeyOnAnEmbedderDriver pins the other side
// of the passkey rejection: a Driver the library did not write is assumed
// to run the ceremony, so construction succeeds.
func TestNew_DoesNotWarnAboutPasskeyOnAnEmbedderDriver(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(passkeyFlowOpts(t), op.WithInteractionDriver(scriptedDriver{}))...); err != nil {
		t.Fatalf("op.New rejected a passkey behind an embedder driver: %v", err)
	}
}
