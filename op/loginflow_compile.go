package op

import (
	"context"
	"errors"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authn/emailotp"
	"github.com/libraz/go-oidc-provider/internal/authn/passkey"
	"github.com/libraz/go-oidc-provider/internal/authn/password"
	"github.com/libraz/go-oidc-provider/internal/authn/recovery"
	"github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// CaptchaSubmissionFieldName is the [interaction.FieldSpec.Name] a
// [StepCaptcha] expects in the SPA submission. The SPA renders the
// upstream provider's challenge widget (Cloudflare Turnstile, Google
// reCAPTCHA, hCaptcha, …) and submits the resulting token under this
// key. The constant is exported so SPA documentation references the
// canonical wire name without a stringly-typed copy.
// The [StepCaptcha] path is independent of the legacy after-N-failures
// captcha gate: a [LoginFlow] without a registered StepCaptcha still
// emits the orchestrator's built-in captcha prompt when
// [State.LastFailures] crosses the threshold (and a
// [WithCaptchaVerifier] is wired). StepCaptcha lets embedders schedule
// captcha through the rule list (e.g., always before TOTP, or only for
// high-risk requests) instead of relying on the threshold gate alone.
const CaptchaSubmissionFieldName = "captcha_token"

// captchaSubmissionMaxLen caps the token bytes the captcha step accepts
// in the submission. Provider tokens (Turnstile / reCAPTCHA / hCaptcha)
// are <= ~2 KiB; 4 KiB is comfortably above the realistic upper bound
// while keeping the parser away from pathological inputs.
const captchaSubmissionMaxLen = 4 * 1024

// errCaptchaTokenMissing surfaces when the SPA omits the captcha token
// field. The orchestrator's [interaction.FieldSpec] validation should
// already have caught this; the adapter re-checks at the trust boundary.
var errCaptchaTokenMissing = errors.New("op: captcha_token field is missing")

// errCaptchaVerifierNil surfaces when [StepCaptcha.Verifier] is nil at
// the time the orchestrator dispatches Continue. The compile path
// rejects a nil verifier at op.New time, so reaching this branch means
// the compiled flow was mutated after compilation — defensive.
var errCaptchaVerifierNil = errors.New("op: StepCaptcha.Verifier is nil")

// captchaStepAdapter wraps a [CaptchaVerifier] as an
// [authn.Authenticator] so the [LoginFlow] orchestrator can drive
// captcha challenges through the same Begin / Continue dispatch path
// as factor-shaped Steps. The wrapper is internal; embedders compose
// captcha through [StepCaptcha].
// The adapter reports an inert [FactorType] / [authn.AAL0] / empty
// AMR so any leak into the factor pipeline is harmless. The orchestrator
// filters captcha-shaped Steps out of [State.Factors] via the compile
// path's IsCaptcha flag, so these values are never aggregated into the
// session AAL or amr_history.
type captchaStepAdapter struct {
	verifier CaptchaVerifier
}

// Type implements [authn.Authenticator]. Returns an inert sentinel
// that is never recorded in [State.Factors] (the LoginFlow compile
// path tags captcha-shaped Steps so [recordLoginFlowResult] skips
// [appendFactor]).
func (captchaStepAdapter) Type() authn.FactorType { return "captcha" }

// AAL implements [authn.Authenticator]. Returns [authn.AAL0]: a
// captcha solve does not raise the session assurance level. The
// LoginFlow orchestrator skips AAL aggregation for captcha-shaped
// Steps anyway; AAL0 is defence-in-depth.
func (captchaStepAdapter) AAL() authn.AAL { return authn.AAL0 }

// AMR implements [authn.Authenticator]. Captcha is not an
// authentication method; the wrapper returns "" so even an accidental
// inclusion in amr_history surfaces as an empty value the orchestrator
// drops on validation.
func (captchaStepAdapter) AMR() string { return "" }

// Prompts implements [authn.Authenticator]. The adapter emits a single
// prompt type matching the orchestrator's legacy captcha prompt so SPAs
// can route both surfaces through one renderer.
func (captchaStepAdapter) Prompts() []string { return []string{"captcha"} }

// Begin implements [authn.Authenticator]. Returns the captcha prompt
// with a single hidden submission field for the upstream provider's
// token. The prompt shape mirrors the orchestrator's legacy
// [emitCaptchaPrompt] so a SPA written for one path renders the other
// without modification.
func (captchaStepAdapter) Begin(_ context.Context, _ authn.BeginInput) (interaction.Step, error) {
	prompt := &interaction.Prompt{
		Type: "captcha",
		Data: interaction.CaptchaPromptData{},
		Inputs: []interaction.FieldSpec{{
			Name:     CaptchaSubmissionFieldName,
			Kind:     interaction.FieldHidden,
			Label:    "auth.captcha.token",
			Required: true,
			MaxLen:   captchaSubmissionMaxLen,
		}},
	}
	return interaction.Step{Prompt: prompt}, nil
}

// Continue implements [authn.Authenticator]. It extracts the captcha
// token from the SPA submission, calls [CaptchaVerifier.Verify], and
// returns a populated [interaction.Result] on success or the verifier
// error on failure. The error never carries the upstream reason — the
// orchestrator surfaces a generic challenge_required so the SPA cannot
// enumerate provider-side rejection codes.
func (a captchaStepAdapter) Continue(ctx context.Context, in authn.ContinueInput) (interaction.Step, error) {
	if a.verifier == nil {
		return interaction.Step{}, errCaptchaVerifierNil
	}
	token, ok := in.Submission.Values[CaptchaSubmissionFieldName]
	if !ok || token == "" {
		return interaction.Step{}, errCaptchaTokenMissing
	}
	if err := a.verifier.Verify(ctx, CaptchaInput{Token: token}); err != nil {
		return interaction.Step{}, err
	}
	return interaction.Step{Result: &interaction.Result{
		Subject:  in.Subject,
		AuthTime: in.AuthTime,
	}}, nil
}

// buildPrimaryPassword constructs the internal [password.Authenticator]
// that drives the [PrimaryPassword] step. The builder validates the
// store dependency up-front so a misconfigured PrimaryPassword
// surfaces at op.New time rather than at the first authorize request.
func buildPrimaryPassword(s PrimaryPassword) (authn.Authenticator, error) { //nolint:ireturn // authn.Authenticator is the orchestrator's contract; concrete factor types are constructor-specific.
	if s.Store == nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "PrimaryPassword.Store is nil",
		}
	}
	return password.NewAuthenticator(s.Store)
}

// buildPrimaryPasskey constructs the internal [passkey.Verifier] +
// [passkey.Authenticator] that drives the [PrimaryPasskey] step. The
// builder validates RP-side configuration up-front so a misconfigured
// PrimaryPasskey surfaces at op.New time rather than at the first
// authorize request.
func buildPrimaryPasskey(s PrimaryPasskey) (authn.Authenticator, error) { //nolint:ireturn // authn.Authenticator is the orchestrator's contract; concrete factor types are constructor-specific.
	if s.Store == nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "PrimaryPasskey.Store is nil",
		}
	}
	v, err := passkey.New(passkey.Config{
		RPID:          s.RPID,
		RPDisplayName: s.RPDisplayName,
		RPOrigins:     s.RPOrigins,
		SessionTTL:    s.SessionTTL,
	})
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "PrimaryPasskey rejected by parser",
			Cause:       err,
		}
	}
	return passkey.NewAuthenticator(v, s.Store)
}

// buildStepTOTP constructs the internal [totp.Codec] + [totp.Verifier]
// + [totp.Authenticator] that drives the [StepTOTP] step. The codec is
// built from the public [StepTOTP.EncryptionKey] and rotation history,
// or — when those fields are empty — from the Provider-level fallback
// configured through [WithMFAEncryptionKey] / [WithMFAEncryptionKeys].
// A non-empty per-step key always wins (more-specific-wins). The
// library never retains the bytes beyond the codec instance.
func buildStepTOTP(s StepTOTP, fallbackCurrent []byte, fallbackPrev [][]byte) (authn.Authenticator, error) { //nolint:ireturn // authn.Authenticator is the orchestrator's contract; concrete factor types are constructor-specific.
	if s.Store == nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "StepTOTP.Store is nil",
		}
	}
	current, prev := selectTOTPKeys(s, fallbackCurrent, fallbackPrev)
	if len(current) == 0 {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "StepTOTP.EncryptionKey is required (or configure WithMFAEncryptionKeys at the Provider level)",
		}
	}
	codec, err := totp.NewCodec(current, prev...)
	if err != nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "StepTOTP rejected by parser",
			Cause:       err,
		}
	}
	verifier := &totp.Verifier{Codec: codec}
	return totp.NewAuthenticator(verifier, s.Store)
}

// selectTOTPKeys resolves the per-step versus Provider-level encryption
// keys for a [StepTOTP]. A non-empty [StepTOTP.EncryptionKey] always
// wins (more-specific-wins); the rotation slot follows the same rule
// independently so an embedder can override only the active key while
// keeping the global rotation history.
func selectTOTPKeys(s StepTOTP, fallbackCurrent []byte, fallbackPrev [][]byte) ([]byte, [][]byte) {
	current := s.EncryptionKey
	if len(current) == 0 {
		current = fallbackCurrent
	}
	prev := s.EncryptionKeyPrev
	if len(prev) == 0 {
		prev = fallbackPrev
	}
	return current, prev
}

// buildStepEmailOTP constructs the internal [emailotp.Authenticator]
// that drives the [StepEmailOTP] step. The public [EmailDelivery]
// adapter is wrapped in a thin [emailotp.Mailer] shim so the internal
// package retains its narrow interface and the public API stays free
// of the [emailotp.Message] payload type.
//
//nolint:ireturn // authn.Authenticator is the orchestrator's contract; concrete factor types are constructor-specific.
func buildStepEmailOTP(s StepEmailOTP) (authn.Authenticator, error) {
	if s.Store == nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "StepEmailOTP.Store is nil",
		}
	}
	if s.Sender == nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "StepEmailOTP.Sender is nil",
		}
	}
	if s.Users == nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "StepEmailOTP.Users is nil",
		}
	}
	mailer := emailotp.MailerFunc(func(ctx context.Context, msg emailotp.Message) error {
		return s.Sender.Send(ctx, msg.To, msg.Code)
	})
	return emailotp.NewAuthenticator(emailotp.Config{
		Mailer:  mailer,
		Store:   s.Store,
		Users:   s.Users,
		CodeTTL: s.CodeTTL,
	})
}

// buildStepRecoveryCode constructs the internal [recovery.Verifier] +
// [recovery.Authenticator] that drives the [StepRecoveryCode] step.
// The verifier carries no construction-time configuration today; the
// argon2id parameters and lockout policy are pinned by
// [internal/authn/recovery].
//
//nolint:ireturn // authn.Authenticator is the orchestrator's contract; concrete factor types are constructor-specific.
func buildStepRecoveryCode(s StepRecoveryCode) (authn.Authenticator, error) {
	if s.Store == nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "StepRecoveryCode.Store is nil",
		}
	}
	verifier := &recovery.Verifier{}
	return recovery.NewAuthenticator(verifier, s.Store)
}

// buildStepCaptcha wraps the [CaptchaVerifier] into the package's
// [captchaStepAdapter] so the LoginFlow orchestrator can drive captcha
// challenges through the same Begin / Continue dispatch path as
// factor-shaped Steps.
//
//nolint:ireturn // authn.Authenticator is the orchestrator's contract; concrete factor types are constructor-specific.
func buildStepCaptcha(s StepCaptcha) (authn.Authenticator, error) {
	if s.Verifier == nil {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "StepCaptcha.Verifier is nil",
		}
	}
	return captchaStepAdapter{verifier: s.Verifier}, nil
}
